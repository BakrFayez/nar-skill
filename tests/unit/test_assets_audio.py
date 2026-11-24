"""Unit tests: nar-assets audio metadata (Evolution Phase 7).

Synthetic fixtures with known headers: a PCM WAV whose
duration is data/byte-rate, an Ogg Vorbis stream whose
final granule is exactly 3 s, MP3 frames (a Xing-counted
stream and a constant-bitrate estimate), and the formats
that must stay UNMEASURED (FLAC, M4A, truncated WAV) —
values are never guessed.
"""
import importlib.util
import os
import struct
import sys
import unittest
import zipfile

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "scripts"))


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(
        name, os.path.join(ROOT, "scripts", filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def make_wav(channels=2, rate=44100, seconds=2):
    byte_rate = rate * channels * 2
    data_size = byte_rate * seconds
    fmt = struct.pack("<HHIIHH", 1, channels, rate, byte_rate,
                      channels * 2, 16)
    return (b"RIFF" + struct.pack("<I", 36 + data_size) + b"WAVE"
            + b"fmt " + struct.pack("<I", 16) + fmt
            + b"data" + struct.pack("<I", data_size)
            + b"\x00" * min(data_size, 64))


def ogg_page(payload_packet, granule, seq=0):
    segs = []
    n = len(payload_packet)
    while n >= 255:
        segs.append(255)
        n -= 255
    segs.append(n)
    header = (b"OggS" + bytes([0, 0])
              + struct.pack("<q", granule)
              + struct.pack("<II", 1, seq)
              + b"\x00\x00\x00\x00" + bytes([len(segs)])
              + bytes(segs))
    return header + payload_packet


def make_ogg_vorbis(rate=22050, seconds=3):
    id_packet = (b"\x01vorbis" + struct.pack("<I", 0)
                 + bytes([2]) + struct.pack("<I", rate)
                 + struct.pack("<iii", 0, 128000, 0)
                 + bytes([1, 1]))
    first = ogg_page(id_packet, 0)
    last = ogg_page(b"\x05vorbis" + b"\x00" * 8, rate * seconds,
                    seq=9)
    return first + last


def mp3_frame_header(bitrate_idx=9, sr_idx=0, chan_mode=0):
    # MPEG1 Layer III, no CRC: FF FB <br/sr/pad> <chan>
    b2 = (bitrate_idx << 4) | (sr_idx << 2)
    b3 = chan_mode << 6
    return bytes([0xFF, 0xFB, b2, b3])


def make_mp3_xing(frames=100):
    # MPEG1 128 kbps 44100 Hz stereo; side info 32 bytes.
    header = mp3_frame_header()
    xing = b"Xing" + struct.pack(">II", 0x1, frames)
    frame = header + b"\x00" * 32 + xing
    frame += b"\x00" * (417 - len(frame))
    return frame * 3


def make_mp3_cbr(total=16000 * 2):
    # No Xing: duration estimate from size at 128 kbps.
    return mp3_frame_header() + b"\x00" * (total - 4)


class AudioMetadataTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.assets = _load("nar_assets_for_test", "nar-assets.py")

    def test_wav_measured_exactly(self):
        data = make_wav()
        meta = self.assets.audio_metadata("wav-audio", data, data,
                                          36 + 8 + 176400)
        self.assertTrue(meta["measured"])
        self.assertEqual(meta["channels"], 2)
        self.assertEqual(meta["sample_rate_hz"], 44100)
        self.assertEqual(meta["duration_seconds"], 2.0)

    def test_ogg_vorbis_measured_from_granule(self):
        data = make_ogg_vorbis()
        meta = self.assets.audio_metadata("ogg-audio", data, data,
                                          len(data))
        self.assertTrue(meta["measured"])
        self.assertEqual(meta["format"], "ogg-vorbis")
        self.assertEqual(meta["channels"], 2)
        self.assertEqual(meta["sample_rate_hz"], 22050)
        self.assertEqual(meta["duration_seconds"], 3.0)

    def test_mp3_xing_frame_count(self):
        data = make_mp3_xing(frames=100)
        meta = self.assets.audio_metadata("mp3-audio", data, data,
                                          len(data))
        self.assertTrue(meta["measured"])
        self.assertEqual(meta["channels"], 2)
        self.assertEqual(meta["sample_rate_hz"], 44100)
        # 100 frames * 1152 samples / 44100 Hz = 2.612 s
        self.assertEqual(meta["duration_seconds"], 2.612)
        self.assertIn("Xing", meta["duration_basis"])

    def test_mp3_cbr_estimate_is_labeled(self):
        data = make_mp3_cbr()
        meta = self.assets.audio_metadata("mp3-audio", data, data,
                                          len(data))
        self.assertTrue(meta["measured"])
        # 32000 bytes * 8 / 128000 bps = 2.0 s
        self.assertEqual(meta["duration_seconds"], 2.0)
        self.assertIn("estimate", meta["duration_basis"])

    def test_unmeasured_formats_stay_unmeasured(self):
        flac = b"fLaC" + b"\x00" * 40
        meta = self.assets.audio_metadata("flac-audio", flac, flac,
                                          len(flac))
        self.assertFalse(meta["measured"])
        self.assertIsNone(meta["duration_seconds"])
        m4a = b"\x00\x00\x00\x18ftypM4A " + b"\x00" * 32
        meta = self.assets.audio_metadata("m4a-audio", m4a, m4a,
                                          len(m4a))
        self.assertFalse(meta["measured"])

    def test_truncated_wav_unmeasured(self):
        meta = self.assets.audio_metadata(
            "wav-audio", b"RIFF\x00\x00", b"", 6)
        self.assertFalse(meta["measured"])

    def test_inventory_attaches_audio_block(self):
        import tempfile
        wav = make_wav()
        with tempfile.TemporaryDirectory() as td:
            apk = os.path.join(td, "audio.apk")
            with zipfile.ZipFile(apk, "w") as zf:
                zf.writestr("assets/sound.wav", wav)
                zf.writestr("assets/notes.txt", "hello")
            report = self.assets.inventory(apk)
        by_path = {a["path"]: a for a in report["assets"]}
        entry = by_path["assets/sound.wav"]
        self.assertTrue(entry["audio"]["measured"])
        self.assertEqual(entry["audio"]["duration_seconds"], 2.0)
        self.assertNotIn("audio", by_path["assets/notes.txt"])


if __name__ == "__main__":
    unittest.main()
