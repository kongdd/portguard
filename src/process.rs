//! Shared streaming subprocess I/O with bounded wait time.
use anyhow::{Result, bail};
use std::{
    io::{Read, Write},
    process::{ChildStdout, Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};

pub fn read_text(mut reader: impl Read) -> Result<String> {
    let mut text = String::new();
    reader.read_to_string(&mut text)?;
    Ok(text)
}

pub fn run<T: Send + 'static>(
    command: &mut Command,
    input: &str,
    timeout: Duration,
    read: impl FnOnce(ChildStdout) -> Result<T> + Send + 'static,
) -> Result<(ExitStatus, T, String)> {
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut stdin = child.stdin.take().unwrap();
    let bytes = input.as_bytes().to_vec();
    let writer = thread::spawn(move || stdin.write_all(&bytes));
    let stdout = child.stdout.take().unwrap();
    let output = thread::spawn(move || read(stdout));
    let stderr = child.stderr.take().unwrap();
    let errors = thread::spawn(move || read_text(stderr));
    let start = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if start.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            bail!("外部命令超过 {} 秒，已中止", timeout.as_secs_f64());
        }
        thread::sleep(Duration::from_millis(10));
    };
    let join_error = |_| anyhow::anyhow!("外部命令 I/O 线程失败");
    let output = output.join().map_err(join_error)??;
    let errors = errors.join().map_err(join_error)??;
    let written = writer.join().map_err(join_error)?;
    if status.success() {
        written?;
    }
    Ok((status, output, errors))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn preserves_output_on_command_failure() {
        let (status, out, err) = run(
            Command::new("sh").args(["-c", "printf out; printf err >&2; exit 7"]),
            "",
            Duration::from_secs(2),
            read_text,
        )
        .unwrap();
        assert_eq!(status.code(), Some(7));
        assert_eq!((out.as_str(), err.as_str()), ("out", "err"));
    }
    #[test]
    fn times_out_and_reaps_child() {
        let start = Instant::now();
        assert!(
            run(
                Command::new("sh").args(["-c", "exec sleep 2"]),
                "",
                Duration::from_millis(20),
                read_text
            )
            .is_err()
        );
        assert!(start.elapsed() < Duration::from_secs(1));
    }
}
