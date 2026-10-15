import { useCallback, useEffect, useRef, useState } from "react";

// Records the head-turn challenge the face service asked for and returns JPEG frames.
// Frames are captured UN-mirrored (what the camera really sees). Only the on-screen
// preview is mirrored with CSS so it feels like a mirror to the user.

type Props = {
  steps: string[];
  title: string;
  busy?: boolean;
  onDone: (frames: Blob[]) => void;
};

type Phase = "idle" | "starting" | "ready" | "countdown" | "capturing" | "sent";

const TEXT: Record<string, string> = {
  center: "Look straight at the camera",
  turn_left: "Slowly turn your head to YOUR left",
  turn_right: "Slowly turn your head to YOUR right",
};
const SETTLE_MS: Record<string, number> = { center: 700, turn_left: 1000, turn_right: 1000 };
const MAX_FRAMES = 24;
const FRAME_GAP_MS = 350;

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

function cameraError(e: unknown): string {
  const name = e instanceof DOMException ? e.name : "";
  if (name === "NotAllowedError" || name === "SecurityError")
    return "Camera permission was blocked. Allow the camera for this site in your browser settings, then try again.";
  if (name === "NotFoundError" || name === "OverconstrainedError")
    return "No camera was found on this device.";
  if (name === "NotReadableError") return "The camera is busy in another app. Close it and try again.";
  return "Could not start the camera.";
}

export default function FaceCapture({ steps, title, busy, onDone }: Props) {
  const videoRef = useRef<HTMLVideoElement>(null);
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const streamRef = useRef<MediaStream | null>(null);
  const alive = useRef(true);
  const [phase, setPhase] = useState<Phase>("idle");
  const [stepIdx, setStepIdx] = useState(-1);
  const [count, setCount] = useState(0);
  const [error, setError] = useState("");

  const stop = useCallback(() => {
    streamRef.current?.getTracks().forEach((t) => t.stop());
    streamRef.current = null;
  }, []);

  useEffect(() => {
    alive.current = true;
    return () => {
      alive.current = false;
      stop();
    };
  }, [stop]);

  async function startCamera() {
    setError("");
    if (!navigator.mediaDevices?.getUserMedia) {
      setError("This browser cannot use the camera here. Open FyberFlix over HTTPS in a current browser.");
      return;
    }
    setPhase("starting");
    try {
      const stream = await navigator.mediaDevices.getUserMedia({
        video: { facingMode: "user", width: { ideal: 1280 }, height: { ideal: 720 } },
        audio: false,
      });
      if (!alive.current) {
        stream.getTracks().forEach((t) => t.stop());
        return;
      }
      streamRef.current = stream;
      const v = videoRef.current;
      if (v) {
        v.srcObject = stream;
        await v.play();
      }
      setPhase("ready");
    } catch (e) {
      setError(cameraError(e));
      setPhase("idle");
    }
  }

  async function grab(): Promise<Blob> {
    const v = videoRef.current;
    if (!v || v.videoWidth === 0) throw new Error("no video");
    const c = (canvasRef.current ??= document.createElement("canvas"));
    const scale = Math.min(1, 800 / Math.max(v.videoWidth, v.videoHeight));
    c.width = Math.round(v.videoWidth * scale);
    c.height = Math.round(v.videoHeight * scale);
    const ctx = c.getContext("2d");
    if (!ctx) throw new Error("no canvas");
    ctx.drawImage(v, 0, 0, c.width, c.height); // raw, not mirrored
    return new Promise<Blob>((res, rej) =>
      c.toBlob((b) => (b ? res(b) : rej(new Error("encode failed"))), "image/jpeg", 0.9),
    );
  }

  async function run() {
    setError("");
    const v = videoRef.current;
    if (!v || v.videoWidth < 320) {
      setError("The camera picture is too small. Try another camera or browser.");
      return;
    }
    setPhase("countdown");
    for (let n = 3; n >= 1; n--) {
      setCount(n);
      await sleep(800);
      if (!alive.current) return;
    }
    setPhase("capturing");
    const perStep = Math.max(2, Math.min(4, Math.floor(MAX_FRAMES / steps.length)));
    const frames: Blob[] = [];
    try {
      for (let i = 0; i < steps.length; i++) {
        setStepIdx(i);
        await sleep(SETTLE_MS[steps[i]] ?? 800); // time to move the head
        for (let k = 0; k < perStep; k++) {
          if (!alive.current) return;
          frames.push(await grab());
          await sleep(FRAME_GAP_MS);
        }
      }
    } catch {
      setError("Could not read the camera. Please try again.");
      setPhase("ready");
      setStepIdx(-1);
      return;
    }
    setPhase("sent");
    stop();
    onDone(frames);
  }

  const active = phase === "capturing" && stepIdx >= 0 ? steps[stepIdx] : null;
  const instruction =
    phase === "countdown"
      ? `Get ready… ${count}`
      : active
        ? (TEXT[active] ?? "Follow the instruction")
        : phase === "sent"
          ? busy
            ? "Checking your face…"
            : "Done"
          : phase === "ready"
            ? "Fit your face inside the oval, in good light"
            : "";

  return (
    <section className="card capture" aria-label={title}>
      <h2>{title}</h2>
      <div className={`stage ${phase === "capturing" ? "live" : ""}`}>
        <video ref={videoRef} playsInline muted className="preview" />
        <div className="oval" aria-hidden="true" />
        {phase === "idle" || phase === "starting" ? (
          <div className="stage-note">Camera is off</div>
        ) : null}
        {phase === "countdown" ? <div className="count">{count}</div> : null}
      </div>

      <p className="instruction" role="status" aria-live="polite">
        {instruction}
      </p>
      {phase === "capturing" ? (
        <ol className="dots" aria-label="progress">
          {steps.map((_s, i) => (
            <li key={i} className={i < stepIdx ? "done" : i === stepIdx ? "now" : ""} />
          ))}
        </ol>
      ) : null}
      {error ? (
        <p className="error" role="alert">
          {error}
        </p>
      ) : null}

      {phase === "idle" || phase === "starting" ? (
        <button className="btn primary" onClick={startCamera} disabled={phase === "starting"}>
          {phase === "starting" ? "Starting camera…" : "Turn on camera"}
        </button>
      ) : null}
      {phase === "ready" ? (
        <button className="btn primary" onClick={run}>
          Start face check
        </button>
      ) : null}

      <ul className="tips">
        <li>Good front light, no strong light behind you.</li>
        <li>No mask, cap or dark glasses.</li>
        <li>Turn only a little (about 30°), keep your eyes on the screen.</li>
        <li>Your photo is not saved: only an encrypted numeric template is.</li>
      </ul>
    </section>
  );
}
