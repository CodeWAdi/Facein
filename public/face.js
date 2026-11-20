// Shared in-browser face recognition helpers (face-api.js). No image ever leaves the browser.
// B14/O3: the library and models are served by FaceIn itself (from node_modules, see server.js), not from a CDN,
// and cached by the browser for 30 days, so the kiosk works without internet access to jsDelivr.
const FACE_API_URL = '/vendor/face-api@1.7.15/face-api.js';
const FACE_MODEL_URL = '/vendor/face-api@1.7.15/model';
let _faceReady = null;
function loadFaceApi() {
  if (_faceReady) return _faceReady;
  _faceReady = new Promise((resolve, reject) => {
    const go = async () => {
      try {
        await faceapi.tf.ready();
        await Promise.all([
          faceapi.nets.tinyFaceDetector.loadFromUri(FACE_MODEL_URL),
          faceapi.nets.faceLandmark68Net.loadFromUri(FACE_MODEL_URL),
          faceapi.nets.faceRecognitionNet.loadFromUri(FACE_MODEL_URL)
        ]);
        resolve(faceapi);
      } catch (e) { _faceReady = null; reject(e); }
    };
    if (window.faceapi) return go();
    const s = document.createElement('script');
    s.src = FACE_API_URL; s.onload = go; s.onerror = () => { _faceReady = null; reject(new Error('Could not load face recognition library')); };
    document.head.appendChild(s);
  });
  return _faceReady;
}
let _stream = null;
async function startCamera(video) {
  if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) throw new Error('Camera needs HTTPS (or localhost) and a supported browser');
  _stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'user', width: { ideal: 640 }, height: { ideal: 480 } }, audio: false });
  video.srcObject = _stream;
  await video.play();
}
function stopCamera() { if (_stream) { _stream.getTracks().forEach(t => t.stop()); _stream = null; } }

// ---------- B12: dim light ----------
// A dark frame is brightened in the browser (gamma curve) before the detector runs. This only helps the detector
// FIND the face; who the face belongs to is still decided by the server with the same threshold and margin (PR #1).
const DARK_LEVEL = 85;      // average brightness (0-255) below which a frame counts as dim
const TARGET_LEVEL = 120;   // brightness the gamma curve aims for
const TOO_DARK_LEVEL = 25;  // below this there is too little signal; the kiosk asks for more light
const _probe = document.createElement('canvas'), _work = document.createElement('canvas');
_probe.width = 32; _probe.height = 24;
const srcSize = s => [s.videoWidth || s.naturalWidth || s.width, s.videoHeight || s.naturalHeight || s.height];
// Average brightness of the frame, measured on a 32x24 thumbnail (cheap).
function frameBrightness(src) {
  const ctx = _probe.getContext('2d', { willReadFrequently: true });
  ctx.drawImage(src, 0, 0, 32, 24);
  const d = ctx.getImageData(0, 0, 32, 24).data;
  let s = 0; for (let i = 0; i < d.length; i += 4) s += 0.299 * d[i] + 0.587 * d[i + 1] + 0.114 * d[i + 2];
  return s / (d.length / 4);
}
let _lut = null, _lutGamma = 0;
function brightenedCopy(src, level) {
  const [w, h] = srcSize(src);
  if (_work.width !== w || _work.height !== h) { _work.width = w; _work.height = h; }
  const ctx = _work.getContext('2d', { willReadFrequently: true });
  ctx.drawImage(src, 0, 0, w, h);
  // gamma so that the current average moves to TARGET_LEVEL; lifts shadows without clipping highlights
  const g = Math.max(0.35, Math.min(1, Math.log(TARGET_LEVEL / 255) / Math.log(Math.max(level, 1) / 255)));
  if (Math.abs(g - _lutGamma) > 0.02 || !_lut) {
    _lut = new Uint8ClampedArray(256); _lutGamma = g;
    for (let v = 0; v < 256; v++) _lut[v] = Math.round(255 * Math.pow(v / 255, g));
  }
  const img = ctx.getImageData(0, 0, w, h), d = img.data;
  for (let i = 0; i < d.length; i += 4) { d[i] = _lut[d[i]]; d[i + 1] = _lut[d[i + 1]]; d[i + 2] = _lut[d[i + 2]]; }
  ctx.putImageData(img, 0, 0);
  return _work;
}

// Returns { descriptor: Float32Array(128), score, brightness, dim } for the single most prominent face,
// or { descriptor: null, score: 0, brightness, dim } when no face is found.
async function readFace(src, inputSize = 320) {
  const brightness = frameBrightness(src);
  const dim = brightness < DARK_LEVEL;
  const input = dim && brightness >= 3 ? brightenedCopy(src, brightness) : src;
  // dim frames: larger detector input (finds smaller/softer faces) and a slightly lower detector cut-off
  const opts = new faceapi.TinyFaceDetectorOptions({ inputSize: dim ? Math.max(inputSize, 416) : inputSize, scoreThreshold: dim ? 0.4 : 0.5 });
  const r = await faceapi.detectSingleFace(input, opts).withFaceLandmarks().withFaceDescriptor();
  return r ? { descriptor: r.descriptor, score: r.detection.score, brightness, dim } : { descriptor: null, score: 0, brightness, dim };
}
function euclid(a, b) { let s = 0; for (let i = 0; i < a.length; i++) { const d = a[i] - b[i]; s += d * d; } return Math.sqrt(s); }
