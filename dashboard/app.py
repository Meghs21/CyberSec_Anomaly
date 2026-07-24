"""
Honeywell AI-Powered Behavioral Anomaly Detection Analyst Dashboard.
Built with Streamlit & Plotly. Focuses on IT + OT mixed enterprise cybersecurity triage.
"""

import sys
import os
import time
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as io
import plotly.graph_objects as go
import streamlit as st
from sklearn.metrics import confusion_matrix, precision_score, recall_score, f1_score

# Ensure parent directory is in sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from data_gen.generator import SyntheticLogGenerator
from detection.baseline import EntityBaselineProfiler
from detection.rule_engine import RuleAssistEngine
from detection.ml_detector import MLAnomalyDetector
from detection.risk_fusion import RiskFusionEngine
from detection.classifier import AnomalyClassifier
from detection.explainer import ExplainabilityEngine

# Set Page Config
st.set_page_config(
    page_title="Honeywell | Behavioral Cyber Anomaly Detection",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for Industrial Dark Mode Aesthetics
st.markdown("""
<style>
    .stApp {
        background-color: #0E1117;
        color: #E0E6ED;
    }
    .metric-card {
        background: linear-gradient(135deg, #1A1F2C 0%, #111520 100%);
        border: 1px solid #2E364F;
        border-radius: 10px;
        padding: 16px;
        box-shadow: 0 4px 20px rgba(0,0,0,0.3);
    }
    .alert-card-critical {
        background: linear-gradient(135deg, #3D0C11 0%, #1F0508 100%);
        border-left: 5px solid #FF3344;
        padding: 14px;
        border-radius: 6px;
        margin-bottom: 12px;
    }
    .alert-card-ot {
        background: linear-gradient(135deg, #3D230C 0%, #241405 100%);
        border-left: 5px solid #FF9900;
        padding: 14px;
        border-radius: 6px;
        margin-bottom: 12px;
    }
    .badge-it {
        background-color: #00A3E0;
        color: white;
        padding: 2px 8px;
        border-radius: 4px;
        font-weight: bold;
        font-size: 11px;
    }
    .badge-ot {
        background-color: #EE3124;
        color: white;
        padding: 2px 8px;
        border-radius: 4px;
        font-weight: bold;
        font-size: 11px;
    }
</style>
""", unsafe_allow_html=True)

@st.cache_data
def load_or_generate_dataset():
    data_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data", "synthetic_access_logs.csv"))
    if os.path.exists(data_path):
        return pd.read_csv(data_path)
    else:
        gen = SyntheticLogGenerator(num_users=50, num_days=14)
        raw_df = gen.generate_logs(target_events=1000)
        final_df = gen.inject_attack_scenarios(raw_df)
        os.makedirs(os.path.dirname(data_path), exist_ok=True)
        final_df.to_csv(data_path, index=False)
        return final_df

@st.cache_resource
def run_detection_pipeline(df):
    """Processes events through the hybrid detection pipeline and returns analyzed dataframe."""
    profiler = EntityBaselineProfiler()
    rule_engine = RuleAssistEngine()
    ml_detector = MLAnomalyDetector()
    risk_fusion = RiskFusionEngine()
    classifier = AnomalyClassifier()
    explainer = ExplainabilityEngine()

    # Pre-train ML detector on normal baseline events
    events = df.to_dict("records")
    ml_detector.fit_normal_baseline(events[:300], profiler)

    analyzed_results = []
    
    for ev in events:
        user_id = ev["user_id"]
        user_domain = ev.get("domain", "IT")
        
        # Get baseline stats
        baseline_stats = profiler.get_baseline_stats(user_id, user_domain)
        
        # Evaluate rules
        rule_signals = rule_engine.evaluate_rules(ev, baseline_stats)
        
        # Extract ML feature vector & score
        feat_vec = ml_detector.extract_features(ev, baseline_stats)
        ml_score = ml_detector.predict_raw_score(feat_vec)
        
        # Fuse risk score
        risk_score, severity, dynamic_thresh = risk_fusion.fuse_risk_score(ev, rule_signals, ml_score, baseline_stats)
        
        # Classify anomaly taxonomy & attack type
        tax_cat, attack_cat = classifier.classify_anomaly(ev, rule_signals, feat_vec, baseline_stats)
        
        # Generate explainability string
        reason = explainer.generate_explanation(ev, rule_signals, feat_vec, baseline_stats, attack_cat)
        
        # Update baseline profile with new event
        profiler.update_profile(ev)
        
        is_alert = risk_score >= dynamic_thresh
        
        res = dict(ev)
        res["risk_score"] = risk_score
        res["severity"] = severity
        res["is_alert"] = is_alert
        res["predicted_taxonomy"] = tax_cat if is_alert else "Normal"
        res["predicted_attack_type"] = attack_cat if is_alert else "None"
        res["explanation"] = reason if is_alert else "Normal behavior within entity baseline thresholds."
        
        analyzed_results.append(res)
        
    return pd.DataFrame(analyzed_results)

def main():
    # Header Banner
    st.markdown("""
        <div style="display: flex; align-items: center; justify-content: space-between; border-bottom: 2px solid #2E364F; padding-bottom: 12px; margin-bottom: 20px;">
            <div>
                <h1 style="color: #FFFFFF; margin: 0; font-size: 26px;">🛡️ Honeywell Cyber Insights</h1>
                <p style="color: #8C9BAE; margin: 4px 0 0 0; font-size: 14px;">AI-Powered Behavioral Anomaly Detection System for Mixed IT + OT Enterprises</p>
            </div>
            <div>
                <span style="background-color: #1E2538; border: 1px solid #3A4566; color: #00C853; padding: 6px 12px; border-radius: 20px; font-size: 12px; font-weight: bold;">
                    ● LIVE SIMULATION ACTIVE
                </span>
            </div>
        </div>
    """, unsafe_allow_html=True)

    # Load & Process Data
    df_raw = load_or_generate_dataset()
    df_analyzed = run_detection_pipeline(df_raw)

    # Sidebar Controls & Filters
    st.sidebar.title("🎛️ Analyst Controls")
    
    domain_filter = st.sidebar.multiselect(
        "Target Asset Domain",
        options=["IT", "OT"],
        default=["IT", "OT"]
    )
    
    min_risk = st.sidebar.slider(
        "Minimum Risk Score Filter",
        min_value=0,
        max_value=100,
        value=60,
        step=5
    )
    
    taxonomy_filter = st.sidebar.multiselect(
        "Anomaly Taxonomy Category",
        options=["Point Anomaly", "Contextual Anomaly", "Collective Anomaly"],
        default=["Point Anomaly", "Contextual Anomaly", "Collective Anomaly"]
    )

    st.sidebar.markdown("---")
    st.sidebar.markdown("### 🧪 Live Pitch Actions")
    if st.sidebar.button("🚨 Trigger Attack Scenario"):
        os.system(f"python {os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'scripts', 'trigger_attack.py'))}")
        st.cache_data.clear()
        st.sidebar.success("Attack burst injected! Reloading dashboard...")
        st.rerun()

    # Filtered Dataframes
    filtered_df = df_analyzed[
        (df_analyzed["asset_domain"].isin(domain_filter)) &
        (df_analyzed["risk_score"] >= min_risk)
    ]

    alerts_df = df_analyzed[df_analyzed["is_alert"]]

    # Top KPI Metrics Cards
    col1, col2, col3, col4, col5 = st.columns(5)
    
    with col1:
        st.markdown(f"""
            <div class="metric-card">
                <div style="color: #8C9BAE; font-size: 12px;">TOTAL EVENTS</div>
                <div style="font-size: 24px; font-weight: bold; color: #FFFFFF;">{len(df_analyzed):,}</div>
                <div style="font-size: 11px; color: #00A3E0;">Processed in Stream</div>
            </div>
        """, unsafe_allow_html=True)

    with col2:
        st.markdown(f"""
            <div class="metric-card">
                <div style="color: #8C9BAE; font-size: 12px;">FLAGGED ALERTS</div>
                <div style="font-size: 24px; font-weight: bold; color: #FFB400;">{len(alerts_df):,}</div>
                <div style="font-size: 11px; color: #FFB400;">Risk Score ≥ Threshold</div>
            </div>
        """, unsafe_allow_html=True)

    with col3:
        it_ot_cross_cnt = len(df_analyzed[df_analyzed["predicted_attack_type"] == "IT-OT Crossover"])
        st.markdown(f"""
            <div class="metric-card">
                <div style="color: #8C9BAE; font-size: 12px;">IT-OT CROSSOVERS</div>
                <div style="font-size: 24px; font-weight: bold; color: #EE3124;">{it_ot_cross_cnt:,}</div>
                <div style="font-size: 11px; color: #EE3124;">Critical OT Asset Misuse</div>
            </div>
        """, unsafe_allow_html=True)

    with col4:
        # Calculate Precision against injected ground truth
        prec = precision_score(df_analyzed["is_attack"], df_analyzed["is_alert"]) * 100
        st.markdown(f"""
            <div class="metric-card">
                <div style="color: #8C9BAE; font-size: 12px;">DETECTION PRECISION</div>
                <div style="font-size: 24px; font-weight: bold; color: #00C853;">{prec:.1f}%</div>
                <div style="font-size: 11px; color: #00C853;">Low False Positive Rate</div>
            </div>
        """, unsafe_allow_html=True)

    with col5:
        rec = recall_score(df_analyzed["is_attack"], df_analyzed["is_alert"]) * 100
        st.markdown(f"""
            <div class="metric-card">
                <div style="color: #8C9BAE; font-size: 12px;">ATTACK RECALL</div>
                <div style="font-size: 24px; font-weight: bold; color: #00A3E0;">{rec:.1f}%</div>
                <div style="font-size: 11px; color: #00A3E0;">Catch Rate vs Ground Truth</div>
            </div>
        """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # Main Tabs
    tab1, tab2, tab3, tab4 = st.tabs([
        "🚨 Live Alert Triage",
        "📊 Live Event Stream",
        "👤 Entity Behavioral Deep-Dive",
        "📈 Model Performance & Ground Truth"
    ])

    # Tab 1: Live Alert Triage
    with tab1:
        st.subheader("High-Risk Security Alerts Feed")
        
        display_alerts = filtered_df[filtered_df["is_alert"]].sort_values(by="risk_score", ascending=False)
        
        if len(display_alerts) == 0:
            st.info("No security alerts matching the current filter criteria.")
        else:
            for idx, row in display_alerts.head(15).iterrows():
                domain_badge = f'<span class="badge-ot">OT / INDUSTRIAL</span>' if row['asset_domain'] == 'OT' else f'<span class="badge-it">IT ENDPOINT</span>'
                card_class = "alert-card-critical" if row['risk_score'] >= 85 or row['predicted_attack_type'] == 'IT-OT Crossover' else "alert-card-ot"
                
                with st.container():
                    st.markdown(f"""
                        <div class="{card_class}">
                            <div style="display: flex; justify-content: space-between; align-items: center;">
                                <div>
                                    <span style="font-size: 18px; font-weight: bold; color: #FFFFFF;">
                                        {row['predicted_attack_type']} ({row['predicted_taxonomy']})
                                    </span>
                                    &nbsp;&nbsp; {domain_badge}
                                </div>
                                <div>
                                    <span style="font-size: 18px; font-weight: bold; color: #FF3344;">
                                        RISK SCORE: {row['risk_score']}/100
                                    </span>
                                </div>
                            </div>
                            <div style="margin-top: 8px; font-size: 13px; color: #C5D1E0;">
                                <strong>User:</strong> {row['user_id']} ({row['role']}) &nbsp;|&nbsp; 
                                <strong>Target Asset:</strong> {row['target_resource']} ({row['asset_domain']}) &nbsp;|&nbsp; 
                                <strong>Time:</strong> {row['timestamp']} &nbsp;|&nbsp; 
                                <strong>Device:</strong> {row['device_id']}
                            </div>
                            <div style="margin-top: 8px; font-size: 13px; color: #FFB400; background-color: rgba(0,0,0,0.3); padding: 8px; border-radius: 4px;">
                                🧠 <strong>Explainability Attribution:</strong> {row['explanation']}
                            </div>
                        </div>
                    """, unsafe_allow_html=True)

    # Tab 2: Live Event Stream Table
    with tab2:
        st.subheader("Real-Time Event Stream Log")
        
        stream_cols = ["timestamp", "user_id", "role", "target_resource", "asset_domain", "mb_transferred", "risk_score", "severity", "predicted_attack_type"]
        st.dataframe(
            filtered_df[stream_cols].sort_values(by="timestamp", ascending=False),
            use_container_width=True,
            column_config={
                "risk_score": st.column_config.ProgressColumn(
                    "Risk Score",
                    help="Continuous risk score from fusion pipeline",
                    format="%d",
                    min_value=0,
                    max_value=100
                )
            }
        )

    # Tab 3: Entity Behavioral Deep-Dive
    with tab3:
        st.subheader("Entity Profile & Baseline Deviation Visualizer")
        
        all_users = sorted(df_analyzed["user_id"].unique())
        selected_user = st.selectbox("Select User Entity to Inspect:", all_users, index=0)
        
        user_events = df_analyzed[df_analyzed["user_id"] == selected_user].copy()
        user_role = user_events["role"].iloc[0]
        user_domain = user_events["domain"].iloc[0]
        
        st.markdown(f"**Entity:** `{selected_user}` &nbsp;|&nbsp; **Role:** `{user_role}` &nbsp;|&nbsp; **Domain:** `{user_domain}`")
        
        u_col1, u_col2 = st.columns(2)
        
        with u_col1:
            # Login Hour Histogram (Normal vs Anomalous)
            user_events["hour"] = user_events["timestamp"].apply(lambda x: int(x.split(" ")[1].split(":")[0]))
            
            fig_hour = px.histogram(
                user_events,
                x="hour",
                color="is_alert",
                nbins=24,
                title="Login Hour Distribution (Normal vs Flagged Alerts)",
                labels={"hour": "Hour of Day (0-23)", "is_alert": "Flagged Alert"},
                color_discrete_map={False: "#00A3E0", True: "#FF3344"},
                barmode="overlay"
            )
            fig_hour.update_layout(template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)")
            st.plotly_chart(fig_hour, use_container_width=True)

        with u_col2:
            # Transfer Volume Scatter over Time
            fig_mb = px.scatter(
                user_events,
                x="timestamp",
                y="mb_transferred",
                color="is_alert",
                size="risk_score",
                title="Data Transfer Volume (MB) over Time",
                labels={"mb_transferred": "MB Transferred", "timestamp": "Timestamp"},
                color_discrete_map={False: "#00C853", True: "#FF3344"}
            )
            fig_mb.update_layout(template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)")
            st.plotly_chart(fig_mb, use_container_width=True)

    # Tab 4: Model Performance & Precision/Recall Metrics
    with tab4:
        st.subheader("Quantitative Evaluation vs Synthetic Ground Truth")
        
        y_true = df_analyzed["is_attack"].astype(int)
        y_pred = df_analyzed["is_alert"].astype(int)
        
        cm = confusion_matrix(y_true, y_pred)
        tn, fp, fn, tp = cm.ravel()
        
        p_val = precision_score(y_true, y_pred)
        r_val = recall_score(y_true, y_pred)
        f1_val = f1_score(y_true, y_pred)
        
        m_col1, m_col2 = st.columns(2)
        
        with m_col1:
            st.markdown("### Confusion Matrix")
            cm_df = pd.DataFrame(
                [[tn, fp], [fn, tp]],
                index=["Actual Normal", "Actual Attack"],
                columns=["Pred Normal", "Pred Attack"]
            )
            st.dataframe(cm_df, use_container_width=True)
            
            st.markdown(f"""
                - **True Positives (TP):** {tp} (Correctly caught attack events)
                - **False Positives (FP):** {fp} (Normal events flagged as attack)
                - **False Negatives (FN):** {fn} (Missed attack events)
                - **True Negatives (TN):** {tn} (Correctly ignored normal events)
            """)

        with m_col2:
            st.markdown("### Metric Summary")
            st.metric("Precision", f"{p_val*100:.2f}%", help="Percentage of raised alerts that are true attacks")
            st.metric("Recall", f"{r_val*100:.2f}%", help="Percentage of injected attacks caught by pipeline")
            st.metric("F1-Score", f"{f1_val:.4f}", help="Harmonic mean of Precision and Recall")
            
            # Anomaly Taxonomy Breakdown Bar Chart
            st.markdown("### Detected Taxonomy Distribution")
            tax_counts = df_analyzed[df_analyzed["is_alert"]]["predicted_taxonomy"].value_counts().reset_index()
            tax_counts.columns = ["Taxonomy", "Count"]
            
            fig_tax = px.bar(
                tax_counts,
                x="Taxonomy",
                y="Count",
                color="Taxonomy",
                color_discrete_sequence=["#FF3344", "#FF9900", "#00A3E0"]
            )
            fig_tax.update_layout(template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)")
            st.plotly_chart(fig_tax, use_container_width=True)

if __name__ == "__main__":
    main()
