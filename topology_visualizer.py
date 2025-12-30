import networkx as nx
import pandas as pd

def generate_topology(df):
    """
    Generates a DOT string for a network topology from a DataFrame.
    
    Args:
        df: DataFrame with columns 'Source', 'Target' (and optional 'Link_Info').
        
    Returns:
        str or None: DOT format string for Graphviz, or None if error.
    """
    try:
        # Expected columns: Source, Target. 
        # If user uploads arbitrary CSV, we try to guess or require standard names.
        
        required_cols = {'Source', 'Target'}
        if not required_cols.issubset(df.columns):
            # Try to map common names
            if 'source' in df.columns: df.rename(columns={'source': 'Source'}, inplace=True)
            if 'target' in df.columns: df.rename(columns={'target': 'Target'}, inplace=True)
            if 'dst' in df.columns: df.rename(columns={'dst': 'Target'}, inplace=True)
            if 'src' in df.columns: df.rename(columns={'src': 'Source'}, inplace=True)
            
        if not required_cols.issubset(df.columns):
             return "Error: CSV must have 'Source' and 'Target' columns."

        G = nx.from_pandas_edgelist(df, 'Source', 'Target')
        
        # Add some styling attributes for Graphviz
        # (Streamlit graphviz_chart uses simplified DOT)
        
        # Convert to DOT
        # NetworkX has a default to_pydot or generic writer. 
        # Streamlit accepts a Graphviz object or dot string.
        # We'll construct a DOT string manually or use nx to simple layout if available.
        # Actually, st.graphviz_chart accepts a graphviz Source object or string.
        
        dot_str = "graph {\n"
        dot_str += '  node [shape=box style=filled fillcolor="#f0f2f6" fontname="Helvetica"];\n'
        dot_str += '  edge [color="#555555"];\n' # Dark gray edges
        
        for u, v in G.edges():
            dot_str += f'  "{u}" -- "{v}";\n'
            
        dot_str += "}"
        
        return dot_str
        
    except Exception as e:
        return f"Error generation topology: {str(e)}"
