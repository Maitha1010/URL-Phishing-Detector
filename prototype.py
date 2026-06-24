"""
prototype.py  —  URL Phishing Detector
---------------------------------------
A Streamlit web app where a user pastes any URL and instantly sees:
  - Whether it is HIGH RISK (likely phishing) or LOW RISK
  - A plain-English explanation of why
  - An optional technical breakdown of the feature signals

Run from the project root:
    D:\\PythonEnvs\\url-phishing-detection\\Scripts\\streamlit run app/prototype.py
"""

import os
import sys
import warnings
warnings.filterwarnings("ignore")

import numpy as np
import pandas as pd
import streamlit as st
import joblib
import shap

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src.feature_extractor import extract_features, SUSPICIOUS_KEYWORDS
from src.explain import build_plain_language_explanation, FEATURE_NAMES

MODELS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "models")


# ── Load model once at startup ────────────────────────────────────────────────
@st.cache_resource(show_spinner="Loading detection model...")
def load_model():
    model    = joblib.load(os.path.join(MODELS_DIR, "xgboost.joblib"))
    explainer = shap.TreeExplainer(model)
    return model, explainer


# ── Analyse one URL ───────────────────────────────────────────────────────────
def analyse_url(url: str, model, explainer):
    """Extract features, run model, compute SHAP, build explanations."""
    features   = extract_features(url)
    feat_array = np.array([[features[f] for f in FEATURE_NAMES]])

    prob        = float(model.predict_proba(feat_array)[0, 1])
    pred_label  = 1 if prob >= 0.5 else 0
    shap_values = explainer.shap_values(feat_array)[0]

    plain = build_plain_language_explanation(
        url, features, shap_values, prob, pred_label
    )

    # Top 8 features ranked by absolute SHAP contribution
    ranked = sorted(
        zip(FEATURE_NAMES, shap_values, [features[f] for f in FEATURE_NAMES]),
        key=lambda x: abs(x[1]),
        reverse=True,
    )[:8]

    return prob, pred_label, features, shap_values, plain, ranked


# ── UI ────────────────────────────────────────────────────────────────────────
def main():
    st.set_page_config(
        page_title="Phishing URL Detector",
        page_icon="🔒",
        layout="centered",
    )

    model, explainer = load_model()

    # ── Header ────────────────────────────────────────────────────────────────
    st.title("🔒 Phishing URL Detector")
    st.markdown(
        "Paste any web address below to check whether it shows signs of phishing. "
        "No network request is made — the analysis is based entirely on the URL text."
    )
    st.markdown("---")

    # ── URL input ─────────────────────────────────────────────────────────────
    url_input = st.text_input(
        "Enter a URL to check:",
        placeholder="e.g. https://www.example.com or http://login-paypal.verify.xyz/update",
    )

    check_clicked = st.button("🔍 Check URL", type="primary", disabled=not url_input.strip())

    # ── Results ───────────────────────────────────────────────────────────────
    if check_clicked and url_input.strip():
        url = url_input.strip()

        with st.spinner("Analysing URL..."):
            prob, pred_label, features, shap_values, plain, ranked = analyse_url(
                url, model, explainer
            )

        st.markdown("---")

        # ── Risk label banner ─────────────────────────────────────────────────
        confidence_pct = round(prob * 100, 1)

        if pred_label == 1:
            st.markdown(
                f"""
                <div style="background:#FFEBEE;border-left:8px solid #EF5350;
                padding:20px;border-radius:8px;margin-bottom:16px">
                <div style="font-size:1.8em;font-weight:bold;color:#B71C1C">
                🔴 HIGH RISK — Likely Phishing</div>
                <div style="color:#C62828;font-size:1.05em;margin-top:6px">
                The model is <b>{confidence_pct}%</b> confident this URL is phishing.</div>
                </div>
                """,
                unsafe_allow_html=True,
            )
        else:
            legit_pct = round((1 - prob) * 100, 1)
            st.markdown(
                f"""
                <div style="background:#E8F5E9;border-left:8px solid #43A047;
                padding:20px;border-radius:8px;margin-bottom:16px">
                <div style="font-size:1.8em;font-weight:bold;color:#1B5E20">
                🟢 LOW RISK — Likely Legitimate</div>
                <div style="color:#2E7D32;font-size:1.05em;margin-top:6px">
                The model is <b>{legit_pct}%</b> confident this URL is legitimate.</div>
                </div>
                """,
                unsafe_allow_html=True,
            )

        # ── Plain-language explanation ─────────────────────────────────────────
        st.subheader("📋 Explanation")
        lines = plain.strip().split("\n")
        for line in lines:
            if line.strip():
                if "HIGH RISK" in line or "LOW RISK" in line:
                    continue   # already shown in the banner above
                st.info(line.strip())

        # ── Disclaimer ────────────────────────────────────────────────────────
        st.caption(
            "⚠️ This tool assists your judgement — it does not replace it. "
            "Even LOW RISK links can sometimes be harmful. "
            "When in doubt, navigate to the website directly rather than clicking a link."
        )

        # ── Technical details (collapsible) ───────────────────────────────────
        with st.expander("🔬 Technical details (feature breakdown)"):
            st.markdown(
                "The table below shows the 8 features that most influenced this decision. "
                "A positive SHAP score means the feature pushed towards **phishing**; "
                "a negative score means it pushed towards **legitimate**."
            )

            rows = []
            for feat, shap_val, val in ranked:
                rows.append({
                    "Feature":           feat.replace("_", " ").title(),
                    "Value":             round(val, 3),
                    "SHAP Score":        f"{shap_val:+.4f}",
                    "Direction":         "→ Phishing" if shap_val > 0 else "→ Legitimate",
                })
            df = pd.DataFrame(rows)

            # Colour the Direction column
            def colour_direction(val):
                if "Phishing" in val:
                    return "color: #C62828; font-weight: bold"
                return "color: #2E7D32; font-weight: bold"

            st.dataframe(
                df.style.applymap(colour_direction, subset=["Direction"]),
                use_container_width=True,
                hide_index=True,
            )

            # Show raw feature values in a second table
            st.markdown("**All 19 extracted features:**")
            all_feats = pd.DataFrame([
                {"Feature": f.replace("_", " ").title(), "Value": round(features[f], 4)}
                for f in FEATURE_NAMES
            ])
            st.dataframe(all_feats, use_container_width=True, hide_index=True)

    # ── Example URLs to try ────────────────────────────────────────────────────
    st.markdown("---")
    st.markdown("**Try these example URLs:**")

    col1, col2 = st.columns(2)
    with col1:
        st.markdown("🔴 **Likely phishing:**")
        st.code("http://secure-login-paypal.verify.xyz/update")
        st.code("http://192.168.1.104/bank-login/verify")
        st.code("http://paypal.com@evil-site.tk/confirm")

    with col2:
        st.markdown("🟢 **Likely legitimate:**")
        st.code("https://www.bbc.co.uk/news")
        st.code("https://www.github.com/login")
        st.code("https://www.amazon.co.uk/orders")


if __name__ == "__main__":
    main()
