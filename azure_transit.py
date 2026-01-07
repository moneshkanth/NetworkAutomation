import networkx as nx
import graphviz

def analyze_transit_routing(peering_pairs):
    """
    Analyzes Azure VNet peering topology for transit routing issues.
    
    Args:
        peering_pairs (list of tuple): [("Hub-VNet", "Spoke-A"), ("Hub-VNet", "Spoke-B")]
    
    Returns:
        dot_source (str): Graphviz DOT format string.
        paths (list of str): Analysis messages.
    """
    G = nx.Graph()
    messages = []
    
    # Build Graph
    for u, v in peering_pairs:
        G.add_node(u)
        G.add_node(v)
        G.add_edge(u, v)
        
    dot = graphviz.Graph(comment='Azure Hub-Spoke Topology')
    dot.attr(rankdir='LR', size='8,5')
    dot.attr('node', shape='box', style='filled', color='lightblue2')
    
    nodes = list(G.nodes())
    edges = list(G.edges())
    
    # Basic Visualization
    for n in nodes:
        color = 'lightblue2'
        if "hub" in n.lower():
            color = 'gold'
        elif "firewall" in n.lower() or "nva" in n.lower():
            color = 'firebrick1'
        dot.node(n, n, fillcolor=color)
        
    for u, v in edges:
        dot.edge(u, v)
        
    # Analyze Transitivity (Spoke to Spoke)
    # Logic: Direct peering is fine. Indirect peering (Hop > 1) requires the middle node to be a Hub/NVA.
    # We find all pairs of leaf nodes (Spokes) and check unique simple paths.
    
    spokes = [n for n in G.degree() if n[1] == 1 and "hub" not in n[0].lower()] # Simple heuristic
    
    import itertools
    for s1, s2 in itertools.combinations(spokes, 2):
        if nx.has_path(G, s1, s2):
            path = nx.shortest_path(G, s1, s2)
            if len(path) > 2: # length is nodes, so >2 nodes means at least 1 intermediary
                # Hop check
                intermediaries = path[1:-1]
                path_str = " <--> ".join(path)
                
                is_valid_transit = False
                for hop in intermediaries:
                    # In a real tool, we'd check checking 'Allow Gateway Transit' flag
                    # Here we check naming convention for 'Hub' or 'FW'
                    if "hub" in hop.lower() or "fw" in hop.lower() or "nva" in hop.lower():
                        is_valid_transit = True
                
                if is_valid_transit:
                     messages.append(f"✅ Route Allowed: {path_str}")
                else:
                     messages.append(f"❌ Broken Transitivity: {path_str} (Intermediate '{intermediaries[0]}' likely needs Gateway Transit enabled or UDR)")
            elif len(path) == 2:
                 messages.append(f"✅ Direct Peering: {s1} <--> {s2}")
        else:
             messages.append(f"❌ No Path: {s1} -/- {s2}")

    return dot.source, messages
