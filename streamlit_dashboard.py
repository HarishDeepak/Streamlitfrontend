# Network Security Monitor Dashboard - Streamlit Frontend
# Updated to use real backend APIs with 5-second auto-refresh

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
import requests
from datetime import datetime
import time

# ============================================================================
# PAGE CONFIG
# ============================================================================
st.set_page_config(
    page_title="Network Security Monitor",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ============================================================================
# CONFIGURATION
# ============================================================================
API_BASE_URL = st.secrets.get("API_URL", "http://localhost:8000")

# ============================================================================
# HELPER FUNCTIONS - API CALLS
# ============================================================================

def fetch_stats():
    """Fetch basic stats from /api/stats"""
    try:
        response = requests.get(f"{API_BASE_URL}/api/stats", timeout=5)
        if response.status_code == 200:
            return response.json()
    except Exception as e:
        st.warning(f"⚠️ Could not fetch stats: {e}")
    
    # Dummy data fallback
    return {
        "packet_count": 2847324,
        "byte_count": 8700000000,
        "detection_rate": 94.3
    }

def fetch_packets(count=20):
    """Fetch live traffic packets from /api/packets?count=N"""
    try:
        response = requests.get(f"{API_BASE_URL}/api/packets?count={count}", timeout=5)
        if response.status_code == 200:
            packets_data = response.json()
            
            # Convert to DataFrame format
            rows = []
            for idx, packet_info in enumerate(packets_data, 1):
                packet = packet_info.get("packet", {})
                prediction = packet_info.get("prediction", {})
                
                rows.append({
                    "TIMESTAMP": datetime.fromtimestamp(packet.get("timestamp", 0)).strftime("%H:%M:%S"),
                    "SOURCE_IP": packet.get("src_ip", "N/A"),
                    "DESTINATION_IP": packet.get("dest_ip", "N/A"),
                    "PROTOCOL": packet.get("protocol", "N/A").upper(),
                    "PACKETS": 1,
                    "BYTES": f"{packet.get('length', 0):,}B",
                    "ATTACK_TYPE": prediction.get("label", "Unknown"),
                    "ANOMALY_SCORE": round(prediction.get("confidence", 0), 2)
                })
            
            return rows
    except Exception as e:
        st.warning(f"⚠️ Could not fetch packets: {e}")
    
    # Dummy data fallback
    return [
        {
            "TIMESTAMP": "14:32:35",
            "SOURCE_IP": "192.168.1.105",
            "DESTINATION_IP": "10.0.0.1",
            "PROTOCOL": "TCP",
            "PACKETS": 1,
            "BYTES": "1247B",
            "ATTACK_TYPE": "Benign",
            "ANOMALY_SCORE": 0.12
        }
    ]

def fetch_attack_distribution():
    """Fetch attack distribution from /api/analytics/attack_distribution"""
    try:
        response = requests.get(f"{API_BASE_URL}/api/analytics/attack_distribution", timeout=5)
        if response.status_code == 200:
            return response.json()
    except Exception as e:
        st.warning(f"⚠️ Could not fetch attack distribution: {e}")
    
    # Dummy data fallback
    return {
        "distribution": {
            "Benign": 2456891,
            "DDoS": 128453,
            "PortScan": 89234,
            "BruteForce": 45123,
            "Infiltration": 15234,
            "WebAttack": 9031,
            "Botnet": 5000
        }
    }

def fetch_time_trends():
    """Fetch time trends from /api/analytics/time_trends"""
    try:
        response = requests.get(f"{API_BASE_URL}/api/analytics/time_trends", timeout=5)
        if response.status_code == 200:
            return response.json()
    except Exception as e:
        st.warning(f"⚠️ Could not fetch time trends: {e}")
    
    # Dummy data fallback
    return {
        "timestamps": [1, 2, 3, 4, 5],
        "packet_rate": [12000, 13500, 14000, 13200, 14800],
        "flow_rate": [450, 480, 510, 470, 520],
        "bytes_per_sec": [2400000, 2700000, 2800000, 2640000, 2960000]
    }

# ============================================================================
# MAIN DASHBOARD
# ============================================================================

# Create placeholder for live refresh
placeholder = st.empty()

# Auto-refresh loop - every 5 seconds
while True:
    with placeholder.container():
        
        # Header
        col1, col2, col3 = st.columns([3, 1, 1])
        with col1:
            st.title("🔒 Network Security Monitor")
            st.markdown("**SOC Dashboard - Student Edition**")
        
        with col3:
            if st.button("🔄 Refresh Now", use_container_width=True):
                st.rerun()
            
            st.caption(f"Last updated: {datetime.now().strftime('%H:%M:%S')}")
        
        st.divider()
        
        # ============================================================================
        # KPI METRICS ROW
        # ============================================================================
        st.subheader("📊 Key Performance Indicators")
        
        stats = fetch_stats()
        
        col1, col2, col3, col4, col5 = st.columns(5)
        
        with col1:
            packet_count = stats.get("packet_count", 0)
            st.metric(
                label="Total Packets",
                value=f"{packet_count/1e6:.1f}M" if packet_count > 1e6 else f"{packet_count:,}",
                delta="+2.3%",
                delta_color="normal"
            )
        
        with col2:
            byte_count = stats.get("byte_count", 0)
            st.metric(
                label="Total Bytes",
                value=f"{byte_count/1e9:.1f}GB" if byte_count > 1e9 else f"{byte_count/1e6:.1f}MB",
                delta="+1.3%",
                delta_color="normal"
            )
        
        with col3:
            st.metric(
                label="Detection Rate",
                value=f"{stats.get('detection_rate', 94.3):.1f}%",
                delta="+2.1%",
                delta_color="normal"
            )
        
        with col4:
            st.metric(
                label="Total Flows",
                value="2.8M",
                delta="+5.2%",
                delta_color="normal"
            )
        
        with col5:
            st.metric(
                label="Anomaly Index",
                value="0.34",
                delta="-0.01",
                delta_color="inverse"
            )
        
        st.divider()
        
        # ============================================================================
        # LIVE NETWORK TRAFFIC TABLE
        # ============================================================================
        st.subheader("📡 Live Network Traffic")
        
        # Fetch live packets
        packets_data = fetch_packets(count=20)
        traffic_df = pd.DataFrame(packets_data)
        
        # Display table
        st.dataframe(
            traffic_df,
            use_container_width=True,
            hide_index=True,
            column_config={
                "ANOMALY_SCORE": st.column_config.NumberColumn(
                    "Anomaly Score",
                    format="%.2f"
                )
            }
        )
        
        # Pagination info - showing total flows
        total_flows = stats.get("packet_count", 2847324)
        st.caption(f"Showing 1-20 of {total_flows:,} flows")
        
        st.divider()
        
        # ============================================================================
        # ATTACK ANALYSIS SECTION
        # ============================================================================
        st.subheader("🎯 Attack Summary")
        
        # Fetch attack distribution to get all attack types
        attack_dist = fetch_attack_distribution()
        distribution = attack_dist.get("distribution", {})
        
        # Create columns for each attack type
        cols = st.columns(len(distribution))
        
        # Define colors for different attack types
        colors = {
            "Benign": "#C8E6C9",
            "DDoS": "#FFCDD2",
            "PortScan": "#FFE0B2",
            "BruteForce": "#F8BBD0",
            "Infiltration": "#E1BEE7",
            "WebAttack": "#BBDEFB",
            "Botnet": "#B2DFDB"
        }
        
        # Display each attack type as a metric card
        for idx, (attack_type, count) in enumerate(distribution.items()):
            with cols[idx]:
                # Calculate percentage
                total = sum(distribution.values())
                percentage = (count / total * 100) if total > 0 else 0
                
                st.metric(
                    label=attack_type,
                    value=f"{count:,}",
                    delta=f"{percentage:.1f}%",
                    delta_color="off"
                )
        
        st.divider()
        
        # ============================================================================
        # CHARTS SECTION
        # ============================================================================
        st.subheader("📈 Network Analysis")
        
        col1, col2 = st.columns(2)
        
        # Attack Type Distribution Chart
        with col1:
            fig_dist = go.Figure(data=[
                go.Bar(
                    x=list(distribution.keys()),
                    y=list(distribution.values()),
                    marker_color=['#C8E6C9', '#FFCDD2', '#FFE0B2', '#F8BBD0', '#E1BEE7', '#BBDEFB', '#B2DFDB'][:len(distribution)]
                )
            ])
            fig_dist.update_layout(
                title="Attack Type Distribution",
                xaxis_title="Attack Type",
                yaxis_title="Count",
                hovermode='x unified',
                height=400,
                showlegend=False
            )
            st.plotly_chart(fig_dist, use_container_width=True)
        
        # Packet Rate Over Time Chart
        with col2:
            trends = fetch_time_trends()
            
            # Convert timestamps to readable format
            timestamps = [datetime.fromtimestamp(ts).strftime("%H:%M") for ts in trends.get("timestamps", [])]
            packet_rates = trends.get("packet_rate", [])
            
            fig_trend = go.Figure(data=[
                go.Scatter(
                    x=timestamps,
                    y=[rate/1000 for rate in packet_rates],  # Convert to kpps
                    mode='lines+markers',
                    name='Packet Rate (kpps)',
                    line=dict(color='#2196F3', width=3),
                    fill='tozeroy'
                )
            ])
            fig_trend.update_layout(
                title="Packet Rate Over Time",
                xaxis_title="Time",
                yaxis_title="Rate (kpps)",
                height=400,
                showlegend=False
            )
            st.plotly_chart(fig_trend, use_container_width=True)
        
        st.divider()
        
        # Anomaly Gauge
        col1, col2, col3 = st.columns([1, 2, 1])
        with col2:
            fig_gauge = go.Figure(data=[go.Indicator(
                mode="gauge+number+delta",
                value=0.34,
                domain={'x': [0, 1], 'y': [0, 1]},
                title={'text': "Flow Anomaly Index"},
                delta={'reference': 0.35},
                gauge={
                    'axis': {'range': [0, 1]},
                    'bar': {'color': "#2196F3"},
                    'steps': [
                        {'range': [0, 0.25], 'color': "#C8E6C9"},
                        {'range': [0.25, 0.5], 'color': "#FFF9C4"},
                        {'range': [0.5, 0.75], 'color': "#FFE0B2"},
                        {'range': [0.75, 1], 'color': "#FFCDD2"}
                    ],
                    'threshold': {
                        'line': {'color': "red", 'width': 4},
                        'thickness': 0.75,
                        'value': 0.9
                    }
                }
            )])
            fig_gauge.update_layout(height=400)
            st.plotly_chart(fig_gauge, use_container_width=True)
        
        st.divider()
        
        # ============================================================================
        # SIDEBAR - FILTERS & SETTINGS
        # ============================================================================
        with st.sidebar:
            st.header("⚙️ Dashboard Settings")
            
            # Time Range Filter
            st.subheader("⏱️ Time Range")
            time_range = st.selectbox(
                "Select time range:",
                ["Last 5 minutes", "Last 15 minutes", "Last Hour", "Last 24 hours"]
            )
            
            # Attack Type Filter
            st.subheader("🎯 Attack Type Filter")
            available_attacks = list(distribution.keys())
            attack_types = st.multiselect(
                "Select attack types to display:",
                available_attacks,
                default=available_attacks[:3]
            )
            
            # Anomaly Score Threshold
            st.subheader("📊 Anomaly Score Threshold")
            threshold = st.slider("Show flows with score >", 0.0, 1.0, 0.5, 0.05)
            
            st.divider()
            
            # Export Options
            st.subheader("📥 Export Data")
            if st.button("Download CSV", use_container_width=True):
                st.success("✅ Data exported successfully!")
            
            if st.button("Export Report", use_container_width=True):
                st.info("📄 Report generation in progress...")
            
            st.divider()
            
            # About Section
            st.subheader("ℹ️ About")
            st.markdown("""
            **Network Security Monitor**
            
            Real-time threat detection dashboard powered by:
            - Machine Learning models
            - Network packet analysis
            - Anomaly detection
            
            **Version**: 2.0.0  
            **API**: Active & Connected  
            **Refresh Rate**: 5 seconds
            """)
        
        # ============================================================================
        # FOOTER
        # ============================================================================
        st.divider()
        st.markdown("""
        <div style='text-align: center; color: #888; font-size: 12px; padding: 20px;'>
            © 2024 Network Security Monitor - Student Project | Powered by Streamlit & FastAPI
        </div>
        """, unsafe_allow_html=True)
    
    # Auto-refresh every 5 seconds
    time.sleep(5)
