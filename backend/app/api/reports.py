from fastapi import APIRouter, Depends, Query, Response
from sqlalchemy.orm import Session
from app.core.db import get_db
from app.services.report_gen import generate_security_report_data
import io

# ReportLab imports for PDF export
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

router = APIRouter(prefix="/reports", tags=["Executive Security Reports"])

@router.get("/summary")
def get_report_summary(days: int = Query(7, ge=1, le=30), db: Session = Depends(get_db)):
    return generate_security_report_data(db, days=days)

@router.get("/export/pdf")
def export_pdf_report(days: int = Query(7, ge=1, le=30), db: Session = Depends(get_db)):
    data = generate_security_report_data(db, days=days)
    
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
    story = []
    styles = getSampleStyleSheet()

    # Title & Subtitle
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontSize=20,
        textColor=colors.HexColor('#00f2fe'),
        spaceAfter=6
    )
    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontSize=10,
        textColor=colors.HexColor('#64748b'),
        spaceAfter=15
    )

    story.append(Paragraph("INTRUSION DETECTION SYSTEM - EXECUTIVE SECURITY REPORT", title_style))
    story.append(Paragraph(f"Generated: {data['generated_at']} | Scope: Last {days} Days | Engine: Snort NIDS", subtitle_style))
    story.append(Spacer(1, 10))

    # Metrics Summary Table
    story.append(Paragraph("<b>1. Security Metrics & Threat Overview</b>", styles['Heading2']))
    metrics = data['metrics']
    m_data = [
        ["Total Intrusion Alerts", str(metrics['total_alerts']), "Critical Alerts", str(metrics['critical'])],
        ["High Severity Alerts", str(metrics['high']), "Medium Severity Alerts", str(metrics['medium'])],
        ["Low Severity Alerts", str(metrics['low']), "Resolved Alerts", str(metrics['resolved'])],
        ["Under Investigation", str(metrics['investigating']), "False Positives", str(metrics['false_positive'])]
    ]
    t_metrics = Table(m_data, colWidths=[140, 100, 140, 100])
    t_metrics.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#0f172a')),
        ('TEXTCOLOR', (0,0), (-1,-1), colors.HexColor('#f8fafc')),
        ('FONTNAME', (0,0), (-1,-1), 'Helvetica'),
        ('FONTSIZE', (0,0), (-1,-1), 9),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#334155')),
        ('PADDING', (0,0), (-1,-1), 6)
    ]))
    story.append(t_metrics)
    story.append(Spacer(1, 15))

    # Top Attack Types & Sources
    story.append(Paragraph("<b>2. Top Attack Vectors & Source IPs</b>", styles['Heading2']))
    at_str = ", ".join([f"{item['type']} ({item['count']})" for item in data['attack_types']])
    src_str = ", ".join([f"{item['ip']} ({item['count']})" for item in data['top_sources']])
    story.append(Paragraph(f"<b>Top Attack Categories:</b> {at_str if at_str else 'None'}", styles['Normal']))
    story.append(Paragraph(f"<b>Most Active Threat Sources:</b> {src_str if src_str else 'None'}", styles['Normal']))
    story.append(Spacer(1, 15))

    # Defensive Actions
    story.append(Paragraph("<b>3. Automated Defensive Mitigation Guidelines</b>", styles['Heading2']))
    for action in data['defensive_actions']:
        story.append(Paragraph(f"<b>Category: {action['attack_type']}</b> (Count: {action['incident_count']})", styles['Heading3']))
        for rec in action['recommendations']:
            story.append(Paragraph(f"• {rec}", styles['Normal']))
        story.append(Spacer(1, 6))

    doc.build(story)
    buffer.seek(0)

    headers = {'Content-Disposition': f'attachment; filename="snort_nids_security_report_{days}d.pdf"'}
    return Response(content=buffer.getvalue(), media_type="application/pdf", headers=headers)
