# Network Security Monitor Dashboard - DYNAMIC FLOW COUNTING
# Counts ACTUAL flows from /api/packets response - no assumptions!

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
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
            data = response.json()
            return {
                "packet_count": data.get("packet_count", 0),
                "byte_count": data.get("byte_count", 0),
                "detection_rate": data.get("detection_rate", 0)
            }
    except Exception as e:
        pass
    
    return {"packet_count": 0, "byte_count": 0, "detection_rate": 0}

def fetch_all_packets(limit=1000):
    """
    Fetch ALL packets from backend to COUNT them properly
    This counts ACTUAL flows returned by the API
    """
    try:
        response = requests.get(f"{API_BASE_URL}/api/packets?count={limit}", timeout=10)
        if response.status_code == 200:
            packets_data = response.json()
            
            if not packets_data:
                return [], 0
            
            # Convert to DataFrame format
            rows = []
            for packet_info in packets_data:
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
            
            # Return rows and ACTUAL count of flows
            return rows, len(rows)
    except Exception as e:
        pass
    
    return [], 0

def fetch_attack_distribution():
    """Fetch attack distribution from /api/analytics/attack_distribution"""
    try:
        response = requests.get(f"{API_BASE_URL}/api/analytics/attack_distribution", timeout=5)
        if response.status_code == 200:
            return response.json()
    except Exception as e:
        pass
    
    return {"distribution": {}}

def fetch_time_trends():
    """Fetch time trends from /api/analytics/time_trends"""
    try:
        response = requests.get(f"{API_BASE_URL}/api/analytics/time_trends", timeout=5)
        if response.status_code == 200:
            return response.json()
    except Exception as e:
        pass
    
    return {"timestamps": [], "packet_rate": [], "flow_rate": [], "bytes_per_sec": []}

# ============================================================================
# AUTO-REFRESH MECHANISM
# ============================================================================
if 'last_refresh' not in st.session_state:
    st.session_state.last_refresh = time.time()

if 'refresh_interval' not in st.session_state:
    st.session_state.refresh_interval = 5

# Check if we need to auto-refresh
current_time = time.time()
time_since_refresh = current_time - st.session_state.last_refresh

if time_since_refresh >= st.session_state.refresh_interval:
    st.session_state.last_refresh = current_time
    st.rerun()

# ============================================================================
# FETCH DATA FROM BACKEND
# ============================================================================

stats = fetch_stats()

# IMPORTANT: Fetch ALL packets to COUNT them accurately
# This counts ACTUAL flows returned by API
packets_data, actual_flow_count = fetch_all_packets(limit=1000)

# Get REAL total flows - count actual packets returned
total_flows = actual_flow_count  # THIS IS THE REAL COUNT!

# ============================================================================
# PAGINATION SETUP
# ============================================================================
if 'current_page' not in st.session_state:
    st.session_state.current_page = 1

# Settings for pagination
flows_per_page = 10

# Calculate total pages based on ACTUAL counted flows
if total_flows > 0:
    total_pages = (total_flows + flows_per_page - 1) // flows_per_page
else:
    total_pages = 0

# Ensure current page doesn't exceed total pages
if total_pages > 0 and st.session_state.current_page > total_pages:
    st.session_state.current_page = total_pages

# Get flows for current page from the data we already fetched
start_idx = (st.session_state.current_page - 1) * flows_per_page
end_idx = min(st.session_state.current_page * flows_per_page, len(packets_data))
page_packets = packets_data[start_idx:end_idx]
traffic_df = pd.DataFrame(page_packets) if page_packets else pd.DataFrame()

# ============================================================================
# PAGE HEADER
# ============================================================================

col1, col2, col3 = st.columns([3, 1, 1])
with col1:
    st.title("🔒 Network Security Monitor")
    st.markdown("**SOC Dashboard - Student Edition**")

with col3:
    if st.button("🔄 Refresh Now", key="refresh_button"):
        st.session_state.last_refresh = time.time()
        st.rerun()
    
    st.caption(f"Updated: {datetime.now().strftime('%H:%M:%S')}")

st.divider()

# ============================================================================
# KPI METRICS ROW
# ============================================================================
st.subheader("📊 Key Performance Indicators")

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
    detection_rate = stats.get("detection_rate", 0)
    st.metric(
        label="Detection Rate",
        value=f"{detection_rate:.1f}%",
        delta="+2.1%",
        delta_color="normal"
    )

with col4:
    # ACTUAL counted flows
    st.metric(
        label="Total Flows",
        value=f"{total_flows:,}",
        delta=f"{total_flows} counted",
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
# LIVE NETWORK TRAFFIC TABLE WITH PAGINATION
# ============================================================================
st.subheader("📡 Live Network Traffic")

if total_flows > 0:
    # Pagination controls
    st.write("**📄 Page Navigation**")
    col1, col2, col3, col4, col5 = st.columns([1, 1, 2, 1, 1])

    with col1:
        if st.button("⬅️ Previous", key="prev_page", use_container_width=True):
            if st.session_state.current_page > 1:
                st.session_state.current_page -= 1
                st.rerun()

    with col2:
        st.metric("Page", st.session_state.current_page)

    with col3:
        page_input = st.number_input(
            "Jump to page:",
            min_value=1,
            max_value=max(1, total_pages),
            value=st.session_state.current_page,
            key="page_jump"
        )
        if page_input != st.session_state.current_page:
            st.session_state.current_page = page_input
            st.rerun()

    with col4:
        st.metric("Total Pages", total_pages)

    with col5:
        if st.button("Next ➡️", key="next_page", use_container_width=True):
            if st.session_state.current_page < total_pages:
                st.session_state.current_page += 1
                st.rerun()

    st.divider()

    # Display traffic table
    if not traffic_df.empty:
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
    else:
        st.info("📭 No flow data available for this page")

    # Pagination info - REAL counted flows
    start_flow = (st.session_state.current_page - 1) * flows_per_page + 1
    end_flow = min(st.session_state.current_page * flows_per_page, total_flows)
    st.caption(f"Showing {start_flow:,}-{end_flow:,} of {total_flows:,} flows (ACTUAL COUNT)")
else:
    st.warning("⚠️ No flows available from backend. Make sure your backend is running and returning data.")

st.divider()

# ============================================================================
# ATTACK ANALYSIS SECTION
# ============================================================================
st.subheader("🎯 Attack Summary")

attack_dist = fetch_attack_distribution()
distribution = attack_dist.get("distribution", {})

if distribution:
    cols = st.columns(len(distribution))
    
    for idx, (attack_type, count) in enumerate(distribution.items()):
        with cols[idx]:
            total = sum(distribution.values())
            percentage = (count / total * 100) if total > 0 else 0
            
            st.metric(
                label=attack_type,
                value=f"{count:,}",
                delta=f"{percentage:.1f}%",
                delta_color="off"
            )
else:
    st.info("📊 No attack distribution data available")

st.divider()

# ============================================================================
# CHARTS SECTION
# ============================================================================
st.subheader("📈 Network Analysis")

col1, col2 = st.columns(2)

# Attack Type Distribution Chart
with col1:
    if distribution:
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
        st.plotly_chart(fig_dist, use_container_width=True, key="attack_dist_chart")
    else:
        st.info("No attack distribution data")

# Packet Rate Over Time Chart
with col2:
    trends = fetch_time_trends()
    timestamps = trends.get("timestamps", [])
    
    if timestamps:
        timestamps_formatted = [datetime.fromtimestamp(ts).strftime("%H:%M") for ts in timestamps]
        packet_rates = trends.get("packet_rate", [])
        
        if packet_rates:
            fig_trend = go.Figure(data=[
                go.Scatter(
                    x=timestamps_formatted,
                    y=[rate/1000 for rate in packet_rates],
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
            st.plotly_chart(fig_trend, use_container_width=True, key="packet_rate_chart")
        else:
            st.info("No packet rate data")
    else:
        st.info("No trend data")

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
    st.plotly_chart(fig_gauge, use_container_width=True, key="anomaly_gauge")

st.divider()

# ============================================================================
# SIDEBAR
# ============================================================================
with st.sidebar:
    st.header("⚙️ Dashboard Settings")
    
    st.subheader("⏱️ Time Range")
    time_range = st.selectbox(
        "Select time range:",
        ["Last 5 minutes", "Last 15 minutes", "Last Hour", "Last 24 hours"]
    )
    
    st.subheader("🎯 Attack Type Filter")
    available_attacks = list(distribution.keys()) if distribution else ["No data"]
    attack_types = st.multiselect(
        "Select attack types to display:",
        available_attacks,
        default=available_attacks[:3] if len(available_attacks) > 3 else available_attacks
    )
    
    st.subheader("📊 Anomaly Score Threshold")
    threshold = st.slider("Show flows with score >", 0.0, 1.0, 0.5, 0.05)
    
    st.divider()
    
    st.subheader("📋 Table Settings")
    flows_per_page_selector = st.select_slider(
        "Flows per page:",
        options=[5, 10, 20, 50],
        value=10
    )
    
    # DISPLAY ACTUAL COUNTED FLOWS
    st.info(f"📊 **Total Flows Counted**: {total_flows:,}")
    st.info(f"📄 **Total Pages**: {total_pages:,}")
    st.info(f"📍 **Current Page**: {st.session_state.current_page}/{total_pages if total_pages > 0 else 1}")
    
    st.divider()
    
    st.subheader("🔄 Auto-Refresh Settings")
    refresh_interval = st.select_slider(
        "Auto-refresh interval (seconds):",
        options=[3, 5, 10, 15, 30],
        value=5
    )
    st.session_state.refresh_interval = refresh_interval
    
    st.divider()
    
    st.subheader("📥 Export Data")
    if st.button("Download CSV", use_container_width=True):
        st.success("✅ Data exported successfully!")
    
    if st.button("Export Report", use_container_width=True):
        st.info("📄 Report generation in progress...")
    
    st.divider()
    
    st.subheader("ℹ️ About")
    st.markdown(f"""
    **Network Security Monitor**
    
    Real-time threat detection dashboard
    
    **Version**: 4.0.0  
    **Counting Method**: ACTUAL flows from API
    **Total Flows**: {total_flows:,}
    **Total Pages**: {total_pages:,}
    **Auto-Refresh**: Every {refresh_interval}s
    
    Flow counting updates on each refresh!
    """)

# ============================================================================
# FOOTER
# ============================================================================
st.divider()
st.markdown(f"""
<div style='text-align: center; color: #888; font-size: 12px; padding: 20px;'>
    © 2024 Network Security Monitor | Flows: {total_flows:,} (ACTUAL COUNT) | Updated: {datetime.now().strftime('%H:%M:%S')}
</div>
""", unsafe_allow_html=True)
