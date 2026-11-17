"""
Push-to-talk voice interface (optional): `agentos voice`.

    Press Enter -> speak for a few seconds -> faster-whisper turns it into text
    -> you CONFIRM the text with the keyboard -> the agent runs -> the answer is spoken.

Everything runs offline. Install the extras first:
    pip install faster-whisper sounddevice numpy
    sudo apt install espeak-ng        (or put a Piper voice in AGENTOS_PIPER_VOICE)
On WSL2 the microphone works through WSLg (Windows 11).

Security: voice is another input channel an attacker could use (a video
playing in the background, an ultrasonic "dolphin attack"). So a transcribed
goal is never run until you confirm it by typing, and tool approvals still
happen on the keyboard, never by voice.
"""

import os
import shutil
import subprocess

from rich.console import Console

console = Console()
SAMPLE_RATE = 16000
_whisper = None


def record(seconds: int):
    import sounddevice as sd
    console.print(f"[bold red]Recording {seconds} s...[/bold red]")
    audio = sd.rec(int(seconds * SAMPLE_RATE), samplerate=SAMPLE_RATE, channels=1, dtype="float32")
    sd.wait()
    return audio.flatten()


def transcribe(audio) -> str:
    global _whisper
    if _whisper is None:
        from faster_whisper import WhisperModel
        # "base.en" is about 150 MB and fast on CPU; int8 keeps RAM use low
        _whisper = WhisperModel(os.getenv("AGENTOS_WHISPER_MODEL", "base.en"), device="cpu", compute_type="int8")
    segments, _ = _whisper.transcribe(audio, language="en", vad_filter=True)
    return " ".join(s.text.strip() for s in segments).strip()


def speak(text: str) -> bool:
    """Say text out loud with Piper (better) or espeak-ng (simpler). Returns False if neither exists."""
    text = text[:600]
    voice = os.getenv("AGENTOS_PIPER_VOICE")
    try:
        if voice and shutil.which("piper") and shutil.which("aplay"):
            wav = subprocess.run(["piper", "--model", voice, "--output_file", "-"], input=text.encode(),
                                 capture_output=True, timeout=60).stdout
            subprocess.run(["aplay", "-q"], input=wav, timeout=60)
            return True
        for cmd in ("espeak-ng", "espeak", "spd-say"):
            if shutil.which(cmd):
                subprocess.run([cmd, text], timeout=60)
                return True
    except (OSError, subprocess.TimeoutExpired):
        pass
    return False


def check_ready():
    missing = []
    for module in ("sounddevice", "numpy", "faster_whisper"):
        try:
            __import__(module)
        except ImportError:
            missing.append(module.replace("_", "-"))
    return missing


def voice_loop(make_agent, seconds=6, listen=None, ask=None):
    """listen() -> text and ask(prompt) -> str can be replaced (tests use fakes)."""
    if listen is None:
        missing = check_ready()
        if missing:
            console.print(f"[red]Voice needs: pip install {' '.join(missing)}[/red]")
            return
        listen = lambda: transcribe(record(seconds))   # noqa: E731
    ask = ask or console.input
    console.print("[bold]Voice mode.[/bold] Enter = talk, q = quit. You confirm every goal before it runs.")
    while True:
        try:
            if ask("\n[bold cyan]\\[Enter] to talk, q to quit: [/bold cyan]").strip().lower() == "q":
                return
        except (EOFError, KeyboardInterrupt):
            return
        text = listen()
        if not text:
            console.print("[yellow]Didn't catch that.[/yellow]")
            continue
        console.print(f"You said: [bold]{text}[/bold]")
        if ask("Run this goal? \\[y/N] ").strip().lower() not in ("y", "yes"):
            console.print("[dim]Not run.[/dim]")
            continue
        result = make_agent().run(text)
        console.print(f"[green]{result.answer}[/green]")
        speak(result.answer)
