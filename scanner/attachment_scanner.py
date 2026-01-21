import base64
import subprocess
import tempfile
import os


def scan_attachments(attachments: list) -> list:
    """
    Scan email attachments using ClamAV.
    Returns list of malware hits.
    """

    findings = []

    if not attachments:
        return findings

    for attachment in attachments:
        filename = attachment.get("filename", "attachment.bin")
        encoded = attachment.get("base64")

        if not encoded:
            continue

        try:
            # Decode base64
            file_bytes = base64.b64decode(encoded)

            with tempfile.NamedTemporaryFile(delete=False) as tmp:
                tmp.write(file_bytes)
                tmp_path = tmp.name

            # Run clamscan
            result = subprocess.run(
                ["clamscan", tmp_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=10,
                text=True
            )

            output = result.stdout.strip()

            if "FOUND" in output:
                findings.append({
                    "filename": filename,
                    "engine": "clamav",
                    "signature": output.split(":")[-1].replace("FOUND", "").strip()
                })

        except Exception as e:
            print("ATTACHMENT_SCAN_ERROR:", repr(e))

        finally:
            try:
                os.remove(tmp_path)
            except Exception:
                pass

    return findings
