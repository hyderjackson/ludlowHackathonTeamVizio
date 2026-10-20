# What the decoder checks

## Legacy representation

Each decoded record is 76 bytes: a little-endian uint32 audio-frame index, followed by 72 one-byte MinHash rank values. All 9,826 baseline records fit that stride. Selected SDK execution checks the serializer and signature generation using synthetic input symbols.

Upstream interpretation: frequency/time features pass through a two-dimensional Haar transform, sparse coefficient signs, packing and MinHash. The sign stage discards magnitudes. These are established algorithmic ideas, not a new fingerprinting algorithm.

## V3 representation

`v3_frames_payload` contains uint32 little-endian frame indices. `v3_fps_payload` contains 63 binary16 little-endian values per vector, totaling 126 bytes. The split is 32 standardized rolling Mel-band magnitude averages plus 31 separately standardized differences between neighboring bands. Every V3 index must appear in the same request's legacy indices. All feature values must be finite.

The V3 script compares the final 31 values against population-standardized adjacent differences of the first 32. The first 32 are already quantized, so this is a tolerance/structure check, not bit-exact reconstruction of the original upstream averages. Disassembly supplies the semantic context.

## Audio cannot simply be saved as a WAV

Base64 decoding yields signatures and feature vectors, not PCM samples. The lossy representations do not uniquely specify the original waveform. Approximate inference with side information has not been ruled out. The separate eight-second source sample is not recovered network audio.

`tools/inspect_message.py` runs a compact structural validator. The bundled fixture is synthetic. The full baseline scripts retain the original analysis logic.
