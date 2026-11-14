// eg25-voice.uc DEV SECONDS OUT [TONE_FILE] — voice over USB on a Quectel EG25-G
// (AT+QPCMV=1,0: the call's PCM on the NMEA port, research/eg25-rpi/NOTES.md).
// Sends a 1 kHz tone up in 20 ms frames, which also keeps the downlink coming,
// and writes the downlink to OUT as 8 kHz s16le mono, sample-aligned.
// With TONE_FILE the uplink is silence until that file exists, then the
// tone: the tool can run from before the dial, so the modem has whole
// frames from the first moment of the call, and the tone start is set by
// whoever creates the file.
//
// ALIGNMENT. The port is a byte stream with no frame marks, and a reader that
// joins a stream already running starts at whatever byte the tty holds: half
// the time inside a sample. Everything after is then read with its bytes
// swapped across samples — loud and distorted, recognisably the call
// (HW-observed on the EG25-G R07A08, 2026-11-13: first sound at an odd byte
// offset). Silence cannot tell, it is all zeros, so the phase is locked on the
// first block with sound: the high byte of an s16le sample stays near 0x00 /
// 0xFF unless the audio is very loud, the low byte does not.
//
// The uplink keeps its 320-byte frames whole: write() may take part of one,
// and the rest goes out first next tick, or every later sample is shifted.
import * as io from 'wwand_io';
import * as uloop from 'uloop';
import * as fs from 'fs';
import * as struct from 'struct';

const FRAME = 320;            // 20 ms at 8 kHz, 16 bit
const LOCK_BLOCK = 640;       // bytes judged together for the phase
const LOCK_MARGIN = 0.2;      // share of "near" bytes one parity must lead by

// DEV '-' replays a capture from $EG25_REPLAY through the aligner, no tty
let replay = (ARGV[0] == '-') ? fs.readfile(getenv('EG25_REPLAY')) : null;
let t = replay ? null : io.open_tty(ARGV[0]);
if (!t && replay == null) { warn('open failed\n'); exit(1); }
let out = fs.open(ARGV[2], 'w');

// whatever the tty buffered before we came is not worth aligning
t?.flush();

// one 1 kHz period = 8 samples at 8 kHz, about -10 dBFS
let frame = '';
for (let i = 0; i < 20; i++)
	for (let v in [ 0, 7326, 10362, 7326, 0, -7326, -10362, -7326 ])
		frame += struct.pack('<h', v);

let silence = '';
for (let i = 0; i < FRAME; i++)
	silence += '\x00';

let tone_file = ARGV[3];

// $EG25_UPLINK: 8 kHz s16le mono raw to send instead of the tone (once,
// then silence) — e.g. ffmpeg -i x.wav -ac 1 -ar 8000 -f s16le x.raw
let up = getenv('EG25_UPLINK') ? fs.readfile(getenv('EG25_UPLINK')) : null;
let up_off = 0;

let next_frame = () => {
	if (up == null)
		return frame;

	let f = substr(up, up_off, FRAME);
	up_off += FRAME;

	// a short last frame is padded: the frames stay whole
	while (length(f) < FRAME)
		f += '\x00';

	return (up_off - FRAME < length(up)) ? f : silence;
};

let st = { rx: 0, tx: 0, partial: 0, phase: null, lock_at: null, dropped: 0, sizes: {},
           tone_at: tone_file ? null : 0 };
let pend = '', hold = '';

let near = (b) => b <= 2 || b >= 253;

// -> 0 or 1 (the parity a sample starts at), or null while undecided
let judge = (buf) => {
	let c = [ 0, 0 ], n = [ 0, 0 ];

	for (let i = 0; i < length(buf); i++) {
		let p = i & 1;
		n[p]++;
		if (near(ord(buf, i)))
			c[p]++;
	}

	let e = c[0] / n[0], o = c[1] / n[1];

	// the high byte is the "near" one; the sample starts one byte before it
	if (o - e > LOCK_MARGIN) return 0;
	if (e - o > LOCK_MARGIN) return 1;
	return null;
};

// Nothing is written until the phase is known: the quiet start of a call is
// often too faint to judge, and written unaligned it is half a second of
// noise. The phase found in a later block holds for all of `hold` (blocks
// start at even offsets in it). Past MAX_HOLD the held part goes out as it
// is, so a silent call still ends up in OUT.
const MAX_HOLD = 64000;       // 4 s
let cur = 0;

let take = (d) => {
	if (st.phase != null)
		return out.write(d);

	hold += d;

	while (length(hold) - cur >= LOCK_BLOCK) {
		let blk = substr(hold, cur, LOCK_BLOCK);
		let p = null;

		// not a regex: the block holds NUL bytes
		for (let i = 0; i < LOCK_BLOCK; i++)
			if (ord(blk, i)) { p = judge(blk); break; }

		if (p != null) {
			st.phase = p;
			st.lock_at = st.rx - length(hold) + cur;
			st.dropped = p;
			out.write(substr(hold, p));
			hold = '';
			return;
		}

		cur += LOCK_BLOCK;

		if (cur >= MAX_HOLD) {
			out.write(substr(hold, 0, cur));
			hold = substr(hold, cur);
			cur = 0;
		}
	}
};

if (replay != null) {
	for (let o = 0; o < length(replay); o += 333) {
		let d = substr(replay, o, 333);
		st.rx += length(d);
		take(d);
	}
	if (length(hold))
		out.write(hold);
	out.close();
	printf('%J\n', st);
	exit(0);
}

uloop.init();

uloop.handle(t.fileno(), () => {
	let d;
	while ((d = t.read()) != null && d !== false) {
		let k = sprintf('%d', length(d));
		st.sizes[k] = (st.sizes[k] ?? 0) + 1;
		st.rx += length(d);
		take(d);
	}
}, uloop.ULOOP_READ);

let tick;
tick = () => {
	if (pend == '') {
		if (st.tone_at == null && fs.access(tone_file))
			st.tone_at = st.tx;
		pend = (st.tone_at != null) ? next_frame() : silence;
	}

	let w = t.write(pend);

	if (type(w) == 'int' && w > 0) {
		if (w < length(pend)) st.partial++;
		st.tx += w;
		pend = substr(pend, w);
	}

	uloop.timer(20, tick);
};
uloop.timer(20, tick);

uloop.timer(+ARGV[1] * 1000, () => uloop.end());
uloop.run();

if (length(hold))
	out.write(hold);
out.close();

printf('%J\n', st);
