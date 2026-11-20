#!/usr/bin/env python3
"""Build sanitized customer kickoff PPTX (no live hostnames/creds)."""
from __future__ import annotations

from pathlib import Path

from pptx import Presentation
from pptx.util import Inches, Pt


def add_bullets(slide, lines: list[str], left=0.8, top=1.8, width=8.5, height=5.0) -> None:
    box = slide.shapes.add_textbox(Inches(left), Inches(top), Inches(width), Inches(height))
    tf = box.text_frame
    tf.clear()
    for i, line in enumerate(lines):
        p = tf.paragraphs[0] if i == 0 else tf.add_paragraph()
        p.text = line
        p.level = 0
        p.font.size = Pt(18)


def main() -> None:
    out = Path(__file__).resolve().parent / "ISE_Audit_Kickoff.pptx"
    prs = Presentation()
    prs.slide_width = Inches(13.333)
    prs.slide_height = Inches(7.5)

    # Title
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    title = slide.shapes.add_textbox(Inches(0.8), Inches(2.5), Inches(11), Inches(1.2))
    title.text_frame.paragraphs[0].text = "Cisco ISE Audit Toolkit"
    title.text_frame.paragraphs[0].font.size = Pt(40)
    sub = slide.shapes.add_textbox(Inches(0.8), Inches(3.7), Inches(11), Inches(1))
    sub.text_frame.paragraphs[0].text = (
        "Read-only assessment · Excel & PDF reports · Air-gapped laptop ready (MIT)"
    )
    sub.text_frame.paragraphs[0].font.size = Pt(20)

    slides_content = [
        (
            "What we do on site",
            [
                "Connect to your ISE Primary Admin Node (HTTPS 443)",
                "Enable API Gateway + OpenAPI if not already on (with your approval)",
                "Pull policy sets, profiles, and related inventory (read-only)",
                "Deliver Excel extract + PDF summary on USB / local folder",
            ],
        ),
        (
            "What you need to provide",
            [
                "PAN IP or FQDN reachable from the assessment laptop",
                "API account: Super Admin or ERS Admin / Operator",
                "Change window if API services must be enabled",
                "Output location for reports (customer-controlled)",
            ],
        ),
        (
            "Laptop pack (no internet required)",
            [
                "Pre-staged Python venv + wheelhouse (offline pip install)",
                "ise-audit scripts from GitHub (MIT)",
                "Local config only — credentials never uploaded",
                "See docs/AIRGAP.md and docs/RUNBOOK.md in the toolkit",
            ],
        ),
        (
            "Run order",
            [
                "1. sdk_smoke.py — confirm OpenAPI",
                "2. ise_policy_export.py — policy CSV/JSON",
                "3. report_excel.py + report_pdf.py — customer deliverables",
                "4. Optional ERS PowerShell pulls when ERS is enabled",
            ],
        ),
        (
            "Security commitments",
            [
                "Read-only audit path by default",
                "Exports stay in your engagement folder — not public git",
                "Tools are MIT; report content remains your data",
                "No cloud / AI dependency on the air-gapped laptop",
            ],
        ),
    ]

    for heading, bullets in slides_content:
        slide = prs.slides.add_slide(prs.slide_layouts[6])
        h = slide.shapes.add_textbox(Inches(0.8), Inches(0.6), Inches(11), Inches(1))
        h.text_frame.paragraphs[0].text = heading
        h.text_frame.paragraphs[0].font.size = Pt(32)
        add_bullets(slide, bullets)

    prs.save(out)
    print(f"Wrote {out}")


if __name__ == "__main__":
    main()
