"""PDF Report generation service."""

from datetime import datetime
from typing import Any

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.platypus import (
        SimpleDocTemplate,
        Table,
        TableStyle,
        Paragraph,
        Spacer,
    )
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False


class ReportGenerator:
    """Generates PDF reports for network audit."""

    def generate(
        self,
        devices: list[dict],
        events: list[dict],
        conf: dict,
    ) -> bytes | None:
        """Generate PDF report from devices and events."""
        if not REPORTLAB_AVAILABLE:
            return None

        buffer = bytes()
        doc = SimpleDocTemplate(buffer, pagesize=A4, leftMargin=2 * cm, rightMargin=2 * cm)

        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            "CustomTitle",
            parent=styles["Heading1"],
            fontSize=18,
            textColor=colors.HexColor("#00D4FF"),
            spaceAfter=20,
        )
        heading_style = ParagraphStyle(
            "CustomHeading",
            parent=styles["Heading2"],
            fontSize=12,
            textColor=colors.HexColor("#1E3A5F"),
            spaceAfter=10,
        )

        story = []

        story.append(
            Paragraph(f"NetWatch - Relatório de Auditoria de Rede", title_style)
        )
        story.append(
            Paragraph(
                f"Org: {conf.get('org_name', 'NetWatch')} | {datetime.now().strftime('%d/%m/%Y %H:%M')}",
                styles["Normal"],
            )
        )
        story.append(Spacer(1, 0.5 * cm))

        story.append(Paragraph("Resumo de Dispositivos", heading_style))
        device_data = [["IP", "MAC", "Hostname", "Vendor", "Risco"]]
        for dev in devices[:50]:
            device_data.append(
                [
                    dev.get("ip", "-"),
                    dev.get("mac", "-")[:17],
                    dev.get("hostname", "-") or "-",
                    dev.get("vendor", "-") or "-",
                    dev.get("risk_level", "INFO"),
                ]
            )

        table = Table(device_data, colWidths=[3 * cm, 4 * cm, 4 * cm, 4 * cm, 2 * cm])
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0D1526")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#00D4FF")),
                    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, 0), 10),
                    ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
                    ("BACKGROUND", (0, 1), (-1, -1), colors.white),
                    ("GRID", (0, 0), (-1, -1), 1, colors.HexColor("#1E3A5F")),
                ]
            )
        )
        story.append(table)
        story.append(Spacer(1, 0.5 * cm))

        if events:
            story.append(Paragraph("Eventos Recentes", heading_style))
            for ev in events[:20]:
                level = ev.get("level", "INFO")
                ts = datetime.fromtimestamp(ev.get("timestamp", 0)).strftime(
                    "%d/%m %H:%M"
                )
                story.append(
                    Paragraph(
                        f"[{ts}] {level}: {ev.get('message', '')}",
                        styles["Normal"],
                    )
                )

        doc.build(story)
        return buffer
