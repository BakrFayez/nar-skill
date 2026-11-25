"""narlib.sqlite: a read-only, pure-bytes SQLite schema parser.

Parses the SQLite file format directly from bytes — the
database header, the page-1 b-tree walk over sqlite_master
ONLY — and reports the schema: tables with their columns,
indexes, views, triggers. It never writes, never executes
SQL, and never opens a target database with the sqlite3
module (that module would create journals/WAL files beside
a target and could run authorizer hooks on hostile files;
parsing the bytes has neither hazard).

Format basis: the public SQLite file-format documentation
(file format 2.0): 100-byte header ("SQLite format 3\\0"),
page size at offset 16, b-tree page types 0x02/0x05/0x0A/0x0D,
table-leaf cell layout (payload size varint, rowid varint,
record header of serial types), overflow pages for payloads
that spill. sqlite_master rows are (type, name, tbl_name,
rootpage, sql); column names/types come from a conservative
parse of the CREATE TABLE statement text carried in sql —
parenthesis matching and top-level comma splitting only,
never a SQL engine.

Bounds: the caller caps the input size; the walk caps the
page count visited and the row count decoded, and any
structural inconsistency degrades the affected record to an
error entry instead of raising.

Part of NAR (Nirous Android Reversing).
MIT License. See LICENSE in the repo root.
"""
import re
import struct

SQLITE_MAGIC = b"SQLite format 3\x00"
MAX_PAGES_WALKED = 4096
MAX_ROWS = 4096


class SqliteError(Exception):
    pass


def _varint(data, off):
    """SQLite varint: 1-9 bytes, big-endian 7-bit groups
    (the 9th byte contributes all 8 bits)."""
    value = 0
    for i in range(9):
        if off + i >= len(data):
            raise SqliteError("varint outside file")
        b = data[off + i]
        if i == 8:
            value = (value << 8) | b
            return value, off + 9
        value = (value << 7) | (b & 0x7F)
        if not (b & 0x80):
            return value, off + i + 1
    return value, off + 9  # unreachable


def _serial_size(serial):
    if serial == 0:
        return 0
    if serial in (1, 2, 3, 4, 5, 6):
        return {1: 1, 2: 2, 3: 3, 4: 4, 5: 6, 6: 8}[serial]
    if serial == 7:
        return 8
    if serial in (8, 9):
        return 0
    if serial in (10, 11):
        return 0  # reserved
    if serial % 2 == 0:
        return (serial - 12) // 2  # blob
    return (serial - 13) // 2      # text


def _serial_value(serial, raw):
    if serial == 0:
        return None
    if serial in (1, 2, 3, 4, 5, 6):
        return int.from_bytes(raw, "big", signed=True)
    if serial == 7:
        return struct.unpack(">d", raw)[0] if len(raw) == 8 else None
    if serial == 8:
        return 0
    if serial == 9:
        return 1
    if serial % 2 == 1 and serial >= 13:
        return raw.decode("utf-8", "replace")
    return raw  # blob: kept as bytes, callers stringify selectively


def _parse_record(payload):
    """One record: header (size varint + serial types) then
    the column values in order."""
    hdr_size, off = _varint(payload, 0)
    if hdr_size > len(payload):
        raise SqliteError("record header larger than payload")
    serials = []
    while off < hdr_size:
        serial, off = _varint(payload, off)
        serials.append(serial)
    values = []
    pos = hdr_size
    for serial in serials:
        size = _serial_size(serial)
        raw = payload[pos:pos + size]
        if len(raw) < size:
            raise SqliteError("record value truncated")
        values.append(_serial_value(serial, raw))
        pos += size
    return values


def _page_payload(data, page_size, page_no, cell_off, payload_len):
    """The full payload of one table-leaf cell, following the
    overflow chain when the payload spills (X = page_size-35
    usable bytes live on the leaf for table b-trees)."""
    usable = page_size
    x = usable - 35
    if payload_len <= x:
        return data[cell_off:cell_off + payload_len]
    keep = x
    out = bytearray(data[cell_off:cell_off + keep])
    ovf_off = cell_off + keep
    if ovf_off + 4 > len(data):
        raise SqliteError("overflow pointer outside file")
    next_page = struct.unpack_from(">I", data, ovf_off)[0]
    remaining = payload_len - keep
    guard = 0
    while next_page and remaining > 0:
        guard += 1
        if guard > MAX_PAGES_WALKED:
            raise SqliteError("overflow chain too long")
        base = (next_page - 1) * page_size
        if base < 0 or base + 4 > len(data):
            raise SqliteError("overflow page outside file")
        nxt = struct.unpack_from(">I", data, base)[0]
        take = min(remaining, usable - 4)
        out += data[base + 4:base + 4 + take]
        remaining -= take
        next_page = nxt
    return bytes(out)


def _walk_table_btree(data, page_size, page_no, rows, depth=0):
    """Collect (rowid, record values) from a table b-tree
    rooted at page_no. Interior pages (0x05) recurse into
    children; leaf pages (0x0D) decode cells."""
    if depth > 32:
        raise SqliteError("b-tree nesting too deep")
    if len(rows) >= MAX_ROWS:
        return
    base = (page_no - 1) * page_size
    if base < 0 or base >= len(data):
        raise SqliteError(f"page {page_no} outside file")
    hdr_off = base + (100 if page_no == 1 else 0)
    if hdr_off + 8 > len(data):
        raise SqliteError("b-tree page header truncated")
    ptype = data[hdr_off]
    if ptype == 0x05:  # interior table page
        ncell = struct.unpack_from(">H", data, hdr_off + 3)[0]
        cell_ptr_base = hdr_off + 12
        rightmost = struct.unpack_from(">I", data, hdr_off + 8)[0]
        for i in range(ncell):
            ptr_at = cell_ptr_base + 2 * i
            if ptr_at + 2 > len(data):
                raise SqliteError("cell pointer array truncated")
            cell_off = base + struct.unpack_from(">H", data, ptr_at)[0]
            if cell_off + 4 > len(data):
                raise SqliteError("interior cell truncated")
            child = struct.unpack_from(">I", data, cell_off)[0]
            _walk_table_btree(data, page_size, child, rows, depth + 1)
            if len(rows) >= MAX_ROWS:
                return
        if rightmost:
            _walk_table_btree(data, page_size, rightmost, rows, depth + 1)
        return
    if ptype != 0x0D:
        raise SqliteError(f"unexpected b-tree page type 0x{ptype:02x}")
    ncell = struct.unpack_from(">H", data, hdr_off + 3)[0]
    cell_ptr_base = hdr_off + 8
    for i in range(ncell):
        if len(rows) >= MAX_ROWS:
            return
        ptr_at = cell_ptr_base + 2 * i
        if ptr_at + 2 > len(data):
            raise SqliteError("cell pointer array truncated")
        cell_off = base + struct.unpack_from(">H", data, ptr_at)[0]
        if cell_off >= len(data):
            raise SqliteError("leaf cell outside file")
        try:
            payload_len, p = _varint(data, cell_off)
            rowid, p = _varint(data, p)
            payload = _page_payload(data, page_size, page_no, p,
                                    payload_len)
            rows.append((rowid, _parse_record(payload)))
        except SqliteError:
            continue  # one corrupt cell never sinks the walk


_CONSTRAINT_WORDS = {
    "primary", "not", "null", "unique", "check", "default",
    "collate", "references", "constraint", "foreign", "key",
}


def parse_create_table_columns(sql):
    """Column (name, declared-type) pairs from a CREATE TABLE
    statement's parenthesised body, by parenthesis matching
    and top-level comma splitting only. Table-level
    constraint clauses (PRIMARY KEY (...), FOREIGN KEY,
    UNIQUE, CHECK, CONSTRAINT) are skipped, as are
    column-constraint tails after the type."""
    if not sql:
        return []
    start = sql.find("(")
    if start < 0:
        return []
    depth = 0
    end = -1
    in_str = None
    for i in range(start, len(sql)):
        ch = sql[i]
        if in_str:
            if ch == in_str:
                in_str = None
            continue
        if ch in ("'", '"', "`"):
            in_str = ch
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                end = i
                break
    if end < 0:
        return []
    body = sql[start + 1:end]
    parts, depth, in_str, cur = [], 0, None, []
    for ch in body:
        if in_str:
            cur.append(ch)
            if ch == in_str:
                in_str = None
            continue
        if ch in ("'", '"', "`"):
            in_str = ch
            cur.append(ch)
        elif ch == "(":
            depth += 1
            cur.append(ch)
        elif ch == ")":
            depth -= 1
            cur.append(ch)
        elif ch == "," and depth == 0:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    if cur:
        parts.append("".join(cur))
    columns = []
    for part in parts:
        part = part.strip()
        if not part:
            continue
        first = re.split(r"\s+", part, maxsplit=1)[0]
        bare = first.strip('"`[]').lower()
        if bare in ("primary", "foreign", "unique", "check",
                    "constraint"):
            continue  # table-level constraint clause
        name = first.strip('"`[]')
        rest = part[len(first):].strip()
        type_tokens = []
        for tok in re.split(r"\s+", rest):
            if not tok:
                continue
            if tok.strip(",").lower() in _CONSTRAINT_WORDS:
                break
            if "(" in tok:  # VARCHAR(20) / DECIMAL(10,2) shape
                type_tokens.append(tok)
                if ")" in tok:
                    break
                continue
            type_tokens.append(tok)
            if len(type_tokens) >= 3:
                break
        columns.append({"name": name,
                        "declared_type": " ".join(type_tokens)
                        or None})
    return columns


def parse_sqlite_schema(data):
    """Parse one SQLite database image (bytes) read-only.

    Returns {status, facts, reason, error} in the house
    parser shape. facts (on success): format_version facts
    from the header (page_size, page_count, encoding,
    user_version, application_id), tables [{name, rootpage,
    columns, sql_present}], indexes [{name, table,
    sql_present, unique}], views [names], triggers [names],
    row counts of sqlite_master by kind. Only sqlite_master
    is walked: table DATA rows are never read."""
    if len(data) < 100 or data[:16] != SQLITE_MAGIC:
        return {"status": "identified_only",
                "fidelity": "identified-only", "facts": {},
                "reason": "not a SQLite database image "
                          "(header magic absent)",
                "error": None}
    page_size = struct.unpack_from(">H", data, 16)[0]
    if page_size == 1:
        page_size = 65536
    if page_size < 512 or page_size & (page_size - 1):
        return {"status": "identified_only",
                "fidelity": "identified-only", "facts": {},
                "reason": f"implausible page size {page_size}",
                "error": None}
    header = {
        "page_size": page_size,
        "file_size_bytes": len(data),
        "page_count": len(data) // page_size,
        "write_version": data[18],
        "read_version": data[19],
        "encoding_code": struct.unpack_from(">I", data, 56)[0],
        "user_version": struct.unpack_from(">I", data, 60)[0],
        "application_id": struct.unpack_from(">I", data, 68)[0],
        "schema_cookie": struct.unpack_from(">I", data, 40)[0],
    }
    header["encoding"] = {1: "utf-8", 2: "utf-16le",
                          3: "utf-16be"}.get(header["encoding_code"])
    header["wal_mode"] = header["read_version"] == 2
    rows = []
    try:
        _walk_table_btree(data, page_size, 1, rows)
    except SqliteError as exc:
        return {"status": "identified_only",
                "fidelity": "identified-only",
                "facts": {"header": header},
                "reason": "sqlite_master walk failed",
                "error": str(exc)}
    tables, indexes, views, triggers = [], [], [], []
    for _rowid, values in rows:
        if len(values) < 5:
            continue
        kind, name, tbl_name, rootpage, sql = values[:5]
        if not isinstance(name, str):
            continue
        sql_text = sql if isinstance(sql, str) else None
        if kind == "table":
            if name.startswith("sqlite_"):
                continue  # internal bookkeeping tables
            tables.append({
                "name": name,
                "rootpage": rootpage if isinstance(rootpage, int)
                else None,
                "columns": parse_create_table_columns(sql_text),
                "sql_present": sql_text is not None,
            })
        elif kind == "index":
            indexes.append({
                "name": name,
                "table": tbl_name if isinstance(tbl_name, str)
                else None,
                "sql_present": sql_text is not None,
                "unique": bool(sql_text and
                               re.search(r"\bUNIQUE\b", sql_text,
                                         re.I)),
                "autoindex": sql_text is None,
            })
        elif kind == "view":
            views.append(name)
        elif kind == "trigger":
            triggers.append(name)
    tables.sort(key=lambda t: t["name"])
    indexes.sort(key=lambda i: i["name"])
    facts = {"header": header, "tables": tables,
             "indexes": indexes, "views": sorted(views),
             "triggers": sorted(triggers),
             "table_count": len(tables),
             "index_count": len(indexes),
             "column_count": sum(len(t["columns"]) for t in tables)}
    return {"status": "supported", "fidelity": "structural-summary",
            "facts": facts, "reason": None, "error": None}
