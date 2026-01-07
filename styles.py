import streamlit as st

def apply_custom_styles():
    st.markdown("""
        <style>
            /* Import Google Fonts: Inter */
            @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');

            :root {
                --bg-color: #F3F4F6; /* Light Grey (Tailwind gray-100) */
                --sidebar-bg: #FFFFFF;
                --card-bg: #FFFFFF;
                --text-primary: #111827; /* Gray-900 */
                --text-secondary: #6B7280; /* Gray-500 */
                --accent-color: #2563EB; /* Bright Blue */
                --border-color: #E5E7EB; /* Gray-200 */
                --shadow-sm: 0 1px 2px 0 rgba(0, 0, 0, 0.05);
                --shadow-md: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
            }

            /* Global Reset */
            html, body, [class*="css"] {
                font-family: 'Inter', sans-serif;
                color: var(--text-primary);
                background-color: var(--bg-color);
            }

            /* Main App Background */
            .stApp {
                background-color: var(--bg-color);
            }

            /* Sidebar Styling */
            [data-testid="stSidebar"] {
                background-color: var(--sidebar-bg);
                border-right: 1px solid var(--border-color);
            }
            [data-testid="stSidebar"] .block-container {
                padding-top: 2rem;
            }
            
            /* Remove Streamlit Decoration */
            header[data-testid="stHeader"] {
                background-color: transparent;
            }
            footer {visibility: hidden;}
            #MainMenu {visibility: hidden;}
            .stDeployButton {display:none;}

            /* ------------------------------------------------------------
               Component Styling: Cards & Metrics
               ------------------------------------------------------------ */
            
            /* Clean White Metric Cards with Shadow */
            [data-testid="stMetric"] {
                background-color: var(--card-bg);
                border: 1px solid var(--border-color);
                border-radius: 8px;
                padding: 1rem;
                box-shadow: var(--shadow-sm);
                transition: box-shadow 0.2s;
            }
            [data-testid="stMetric"]:hover {
                box-shadow: var(--shadow-md);
            }
            [data-testid="stMetricLabel"] {
                color: var(--text-secondary);
                font-size: 0.875rem;
                font-weight: 500;
            }
            [data-testid="stMetricValue"] {
                color: var(--text-primary);
                font-weight: 700;
                font-size: 1.5rem;
            }

            /* ------------------------------------------------------------
               Input Widgets (Clean & Airy)
               ------------------------------------------------------------ */
             
            /* Text Input, Number Input, Select Box */
            .stTextInput > div > div > input,
            .stNumberInput > div > div > input {
                background-color: #FFFFFF;
                color: var(--text-primary);
                border: 1px solid var(--border-color);
                border-radius: 6px;
                padding: 0.5rem;
                box-shadow: var(--shadow-sm);
            }
            
            /* Focus states - distinct blue ring */
            .stTextInput > div > div > input:focus,
            .stNumberInput > div > div > input:focus {
                border-color: var(--accent-color);
                box-shadow: 0 0 0 2px rgba(37, 99, 235, 0.2); /* Blue ring with opacity */
            }

            /* Selectbox */
            .stSelectbox > div > div {
                background-color: #FFFFFF;
                border: 1px solid var(--border-color);
                border-radius: 6px;
                color: var(--text-primary);
                box-shadow: var(--shadow-sm);
            }

            /* Buttons: Primary vs Light */
            .stButton > button {
                background-color: #FFFFFF;
                color: var(--text-primary);
                border: 1px solid var(--border-color);
                border-radius: 6px;
                font-weight: 500;
                padding: 0.5rem 1rem;
                box-shadow: var(--shadow-sm);
                transition: all 0.2s;
            }
            .stButton > button:hover {
                border-color: #D1D5DB; /* Gray-300 */
                background-color: #F9FAFB; /* Gray-50 */
                box-shadow: var(--shadow-md);
            }
            
            /* Primary Button Override (if user sets type="primary") */
            button[kind="primary"] {
                background-color: var(--accent-color);
                color: white;
                border: none;
            }
            button[kind="primary"]:hover {
                background-color: #1D4ED8; /* Darker blue */
                box-shadow: var(--shadow-md);
            }

            /* DataFrames */
            [data-testid="stDataFrame"] {
                border: 1px solid var(--border-color);
                border-radius: 8px;
                background-color: #FFFFFF;
                box-shadow: var(--shadow-sm);
            }

            /* Headings */
            h1 {
                font-weight: 700;
                letter-spacing: -0.025em;
                color: #111827;
            }
            h2, h3 {
                font-weight: 600;
                color: #374151; /* Gray-700 */
                letter-spacing: -0.025em;
            }

            /* Expander */
            .streamlit-expanderHeader {
                background-color: #FFFFFF;
                border: 1px solid var(--border-color);
                border-radius: 6px;
                color: var(--text-primary);
                box-shadow: var(--shadow-sm);
            }
            
            /* Dividers */
            hr {
                border-color: var(--border-color);
                margin: 2rem 0;
            }
            
            /* Images */
            img {
                border-radius: 8px;
                box-shadow: var(--shadow-md);
            }

            /* ------------------------------------------------------------
               Mobile Responsiveness
               ------------------------------------------------------------ */
            @media (max-width: 640px) {
                .block-container {
                     padding-top: 3rem;
                     padding-left: 1rem;
                     padding-right: 1rem;
                }
                
                h1 { font-size: 1.5rem; }
                [data-testid="stMetricValue"] { font-size: 1.25rem; }
                
                .stButton > button {
                    width: 100%;
                }
            }

        </style>
    """, unsafe_allow_html=True)
