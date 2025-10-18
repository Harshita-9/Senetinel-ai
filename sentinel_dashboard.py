import streamlit as st
import requests
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import time

st.set_page_config(
    page_title="SENTINEL AI - Security Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

API_BASE_URL = "http://localhost:8000"

st.markdown("""
<style>
    .main-header {
        font-size: 3rem;
        font-weight: bold;
        text-align: center;
        background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 2rem;
    }
    .metric-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 1.5rem;
        border-radius: 10px;
        color: white;
        text-align: center;
    }
    .severity-critical {
        background-color: #dc2626;
        color: white;
        padding: 0.25rem 0.75rem;
        border-radius: 5px;
        font-weight: bold;
    }
    .severity-high {
        background-color: #ea580c;
        color: white;
        padding: 0.25rem 0.75rem;
        border-radius: 5px;
        font-weight: bold;
    }
    .severity-medium {
        background-color: #f59e0b;
        color: white;
        padding: 0.25rem 0.75rem;
        border-radius: 5px;
        font-weight: bold;
    }
    .severity-low {
        background-color: #10b981;
        color: white;
        padding: 0.25rem 0.75rem;
        border-radius: 5px;
        font-weight: bold;
    }
</style>
""", unsafe_allow_html=True)

def get_dashboard_data():
    try:
        response = requests.get(f"{API_BASE_URL}/api/dashboard", timeout=5)
        if response.status_code == 200:
            return response.json()
    except:
        pass
    return None

def get_incidents(limit=50):
    try:
        response = requests.get(f"{API_BASE_URL}/api/incidents?limit={limit}", timeout=5)
        if response.status_code == 200:
            return response.json()
    except:
        pass
    return []

def get_incident_detail(incident_id):
    try:
        response = requests.get(f"{API_BASE_URL}/api/incidents/{incident_id}", timeout=5)
        if response.status_code == 200:
            return response.json()
    except:
        pass
    return None

def get_stats():
    try:
        response = requests.get(f"{API_BASE_URL}/api/stats", timeout=5)
        if response.status_code == 200:
            return response.json()
    except:
        pass
    return {}

st.markdown('<h1 class="main-header">🛡️ SENTINEL AI - Autonomous Security Analyst</h1>', unsafe_allow_html=True)

st.markdown("---")

col1, col2, col3, col4, col5 = st.columns(5)

dashboard_data = get_dashboard_data()
stats = get_stats()

if dashboard_data:
    with col1:
        st.metric(
            "Total Incidents",
            f"{dashboard_data.get('total_incidents', 0):,}",
            delta=f"{stats.get('incidents_last_24h', 0)} (24h)"
        )
    
    with col2:
        st.metric(
            "Resolved",
            f"{dashboard_data.get('resolved', 0):,}",
            delta=f"{dashboard_data.get('auto_resolved', 0)} auto"
        )
    
    with col3:
        automation_rate = dashboard_data.get('automation_rate', 0)
        st.metric(
            "Automation Rate",
            f"{automation_rate:.1f}%",
            delta="AI-Powered"
        )
    
    with col4:
        prevented_cost = stats.get('total_prevented_cost', 0)
        st.metric(
            "Cost Prevented",
            f"${prevented_cost:,.0f}",
            delta="Estimated"
        )
    
    with col5:
        st.metric(
            "Active Playbooks",
            f"{dashboard_data.get('total_playbooks', 0)}",
            delta="Learning"
        )

st.markdown("---")

tab1, tab2, tab3, tab4 = st.tabs(["🎯 Live Monitoring", "📊 Analytics", "📚 Incidents", "🤖 Agents"])

with tab1:
    st.subheader("Real-Time Threat Detection")
    
    col1, col2 = st.columns(2)
    
    with col1:
        if dashboard_data and dashboard_data.get('by_severity'):
            severity_data = dashboard_data['by_severity']
            
            fig = go.Figure(data=[go.Pie(
                labels=list(severity_data.keys()),
                values=list(severity_data.values()),
                hole=0.4,
                marker_colors=['#10b981', '#f59e0b', '#ea580c', '#dc2626']
            )])
            fig.update_layout(
                title="Incidents by Severity",
                height=400
            )
            st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        if dashboard_data and dashboard_data.get('by_type'):
            type_data = dashboard_data['by_type']
            
            fig = px.bar(
                x=list(type_data.keys()),
                y=list(type_data.values()),
                title="Incidents by Attack Type",
                labels={'x': 'Attack Type', 'y': 'Count'},
                color=list(type_data.values()),
                color_continuous_scale='viridis'
            )
            fig.update_layout(height=400)
            st.plotly_chart(fig, use_container_width=True)
    
    st.subheader("Agent Status")
    
    if dashboard_data and dashboard_data.get('agent_states'):
        agents_col = st.columns(5)
        agent_names = ['Watcher', 'Investigator', 'Healer', 'Economist', 'Librarian']
        
        for idx, (agent_key, agent_name) in enumerate(zip(
            ['watcher', 'investigator', 'healer', 'economist', 'librarian'],
            agent_names
        )):
            with agents_col[idx]:
                state = dashboard_data['agent_states'].get(agent_key, 'idle')
                emoji = "🟢" if state == "active" else "🔵" if state == "idle" else "🔴"
                st.markdown(f"### {emoji} {agent_name}")
                st.markdown(f"**Status:** {state.upper()}")

with tab2:
    st.subheader("Security Analytics")
    
    incidents = get_incidents(100)
    
    if incidents:
        df = pd.DataFrame(incidents)
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        df['date'] = df['timestamp'].dt.date
        
        daily_counts = df.groupby('date').size().reset_index(name='count')
        
        fig = px.line(
            daily_counts,
            x='date',
            y='count',
            title='Incident Trend Over Time',
            labels={'date': 'Date', 'count': 'Number of Incidents'}
        )
        fig.update_layout(height=400)
        st.plotly_chart(fig, use_container_width=True)
        
        col1, col2 = st.columns(2)
        
        with col1:
            attack_type_counts = df['attack_type'].value_counts().head(10)
            fig = px.bar(
                x=attack_type_counts.index,
                y=attack_type_counts.values,
                title='Top 10 Attack Types',
                labels={'x': 'Attack Type', 'y': 'Count'}
            )
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            status_counts = df['status'].value_counts()
            fig = px.pie(
                names=status_counts.index,
                values=status_counts.values,
                title='Incident Status Distribution',
                hole=0.3
            )
            st.plotly_chart(fig, use_container_width=True)

with tab3:
    st.subheader("Recent Security Incidents")
    
    col1, col2 = st.columns([3, 1])
    
    with col1:
        search = st.text_input("🔍 Search incidents", placeholder="Search by ID, IP, or attack type...")
    
    with col2:
        severity_filter = st.selectbox(
            "Filter by Severity",
            ["All", "critical", "high", "medium", "low"]
        )
    
    incidents = get_incidents(50)
    
    if incidents:
        for incident in incidents:
            if severity_filter != "All" and incident['severity'] != severity_filter:
                continue
            
            if search and search.lower() not in str(incident).lower():
                continue
            
            with st.expander(
                f"🚨 {incident['attack_type'].upper()} - {incident['timestamp']} - "
                f"{incident['severity'].upper()}"
            ):
                col1, col2, col3 = st.columns(3)
                
                with col1:
                    st.markdown(f"**Incident ID:** `{incident['id']}`")
                    st.markdown(f"**Source IP:** `{incident['source_ip']}`")
                
                with col2:
                    st.markdown(f"**Severity:** `{incident['severity']}`")
                    st.markdown(f"**Status:** `{incident['status']}`")
                
                with col3:
                    st.markdown(f"**Confidence:** `{incident['confidence_score']:.2%}`")
                    st.markdown(f"**Auto-Resolved:** `{incident.get('auto_resolved', False)}`")
                
                if st.button(f"View Details", key=incident['id']):
                    detail = get_incident_detail(incident['id'])
                    if detail:
                        st.json(detail)

with tab4:
    st.subheader("Multi-Agent System Overview")
    
    st.markdown("""
    ### 🤖 Autonomous Agent Architecture
    
    SENTINEL operates through coordinated AI agents, each specialized in a critical security function:
    """)
    
    agents_info = [
        {
            "name": "👁️ Watcher Agent",
            "role": "Threat Detection",
            "capabilities": [
                "Real-time network traffic monitoring",
                "Honeypot management",
                "ML-based anomaly detection",
                "Signature-based threat identification"
            ]
        },
        {
            "name": "🔍 Investigator Agent",
            "role": "Incident Analysis",
            "capabilities": [
                "Attack chain reconstruction",
                "Root cause analysis",
                "Similar incident correlation",
                "AI-powered threat intelligence"
            ]
        },
        {
            "name": "⚕️ Healer Agent",
            "role": "Automated Remediation",
            "capabilities": [
                "Autonomous threat containment",
                "Vulnerability patching",
                "System isolation",
                "Rollback mechanism"
            ]
        },
        {
            "name": "💰 Economist Agent",
            "role": "Financial Impact Analysis",
            "capabilities": [
                "Real-time breach cost calculation",
                "Regulatory fine estimation",
                "Business impact assessment",
                "Executive reporting"
            ]
        },
        {
            "name": "📚 Librarian Agent",
            "role": "Knowledge Management",
            "capabilities": [
                "Incident documentation",
                "Playbook generation",
                "Compliance reporting",
                "Historical analysis"
            ]
        }
    ]
    
    cols = st.columns(3)
    
    for idx, agent in enumerate(agents_info):
        with cols[idx % 3]:
            st.markdown(f"### {agent['name']}")
            st.markdown(f"**Role:** {agent['role']}")
            st.markdown("**Capabilities:**")
            for cap in agent['capabilities']:
                st.markdown(f"- {cap}")
            st.markdown("---")
    
    st.subheader("System Performance Metrics")
    
    if stats:
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.metric(
                "Knowledge Base Size",
                f"{stats.get('total_incidents', 0)} incidents",
                help="Total incidents documented in knowledge base"
            )
        
        with col2:
            st.metric(
                "Playbook Library",
                f"{stats.get('total_playbooks', 0)} playbooks",
                help="Automated response playbooks generated"
            )
        
        with col3:
            automation = stats.get('automation_rate', 0)
            st.metric(
                "Self-Learning Rate",
                f"{automation:.1f}%",
                help="Percentage of incidents resolved autonomously"
            )

st.markdown("---")
st.markdown("""
<div style='text-align: center; color: #666;'>
    <p><strong>SENTINEL AI</strong> - The World's First Autonomous Security Analyst</p>
    <p>Powered by Multi-Agent AI Architecture | Real-time Threat Intelligence | Autonomous Response</p>
</div>
""", unsafe_allow_html=True)

if st.sidebar.checkbox("🔄 Auto-refresh (10s)", value=False):
    time.sleep(10)
    st.rerun()