import re

class RouteEntry:
    def __init__(self, prefix, as_path=None, communities=None, local_pref=100, med=0, origin="IGP"):
        self.prefix = prefix
        self.as_path = as_path if as_path else []
        self.communities = set(communities) if communities else set()
        self.local_pref = local_pref
        self.med = med
        self.origin = origin
        self.action = "Implicit Deny" # Default action if no match found
        self.logs = []

    def to_dict(self):
        return {
            "prefix": self.prefix,
            "as_path": self.as_path,
            "communities": sorted(list(self.communities)),
            "local_pref": self.local_pref,
            "med": self.med,
            "origin": self.origin,
            "action": self.action
        }

    def log(self, message):
        self.logs.append(message)

def parse_route_map(config_text):
    """
    Parses a text-based route-map configuration into a structured list of clauses.
    Returns a dict keyed by route-map name.
    """
    route_maps = {}
    current_map = None
    current_clause = None

    lines = config_text.splitlines()
    for line in lines:
        line = line.strip()
        if not line or line.startswith("!"):
            continue

        # Parse Header: route-map NAME permit|deny SEQ
        # Ex: route-map RM_Inbound permit 10
        match_header = re.match(r"route-map\s+(\S+)\s+(permit|deny)\s+(\d+)", line, re.IGNORECASE)
        if match_header:
            map_name = match_header.group(1)
            action = match_header.group(2).lower()
            seq = int(match_header.group(3))

            if map_name not in route_maps:
                route_maps[map_name] = []
            
            current_clause = {
                "seq": seq,
                "action": action,
                "matches": [],
                "sets": []
            }
            route_maps[map_name].append(current_clause)
            continue

        if current_clause is None:
            continue

        # Parse Matches
        if line.startswith("match"):
            # match ip address prefix-list NAME
            # match as-path NAME
            # match community NAME
            current_clause["matches"].append(line)

        # Parse Sets
        elif line.startswith("set"):
            # set local-preference 200
            # set community 100:1 additive
            current_clause["sets"].append(line)
        
        # Parse Continue (advanced, skipping for MVP)
    
    # Sort clauses by sequence
    for rm in route_maps:
        route_maps[rm].sort(key=lambda x: x["seq"])
        
    return route_maps

def simulate_route_map(route_entry, route_map_clauses):
    """
    Simulates the flow of a route entry through a list of route-map clauses.
    Modifies the route_entry in place.
    """
    route_entry.log(f"Starting simulation...")
    
    matched_final = False

    for clause in route_map_clauses:
        seq = clause['seq']
        action = clause['action']
        route_entry.log(f"Processing Sequence {seq} ({action.upper()})")

        # Check Matches
        matches_all = True
        if not clause['matches']:
            route_entry.log(f"  - No match conditions (Match All)")
        
        for match_cmd in clause['matches']:
            # match ip address prefix-list PL_NAME
            # simplified logic: we verify if the match command *contains* the prefix for this MVP
            # In a real tool, we'd parse the prefix-list separately.
            
            # MOCK LOGIC: If the match command allows everything or specific mock checks
            if "prefix-list" in match_cmd:
                # Mock: Check if prefix is valid
                route_entry.log(f"  - Checking {match_cmd} (Mock: Passed)")
            elif "as-path" in match_cmd:
                 route_entry.log(f"  - Checking {match_cmd} (Mock: Passed)")
            else:
                 route_entry.log(f"  - Checking {match_cmd} (Mock: Passed)")

        if matches_all:
            route_entry.log(f"  - Conditions Matched!")
            if action == "deny":
                 route_entry.action = "DENIED"
                 route_entry.log(f"RESULT: Route Denied at seq {seq}")
                 return route_entry
            
            # Apply Sets
            route_entry.action = "PERMITTED"
            if clause['sets']:
                for set_cmd in clause['sets']:
                    apply_set_command(route_entry, set_cmd)
            
            route_entry.log(f"RESULT: Route Permitted at seq {seq}")
            return route_entry
        else:
             route_entry.log(f"  - Conditions NOT matched, moving to next sequence.")

    route_entry.log("End of Route-Map: Implicit Deny")
    route_entry.action = "DENIED (Implicit)"
    return route_entry

def apply_set_command(route, cmd):
    """Applies set logic to the route object."""
    # set local-preference 200
    if "local-preference" in cmd:
        try:
            val = int(cmd.split()[-1])
            route.local_pref = val
            route.log(f"    -> Set Local-Pref to {val}")
        except:
            route.log(f"    -> Error parsing: {cmd}")
            
    # set community 100:1 additive
    elif "community" in cmd:
        parts = cmd.split()
        # simplified: find the community string
        # format: set community 65000:100 [additive]
        new_comms = []
        is_additive = "additive" in cmd
        
        for p in parts:
            if ":" in p and not p.startswith("community"):
                new_comms.append(p)
        
        if not is_additive:
            route.communities = set(new_comms)
            route.log(f"    -> Overwrote communities to {new_comms}")
        else:
            route.communities.update(new_comms)
            route.log(f"    -> Added communities {new_comms}")
            
    # set med 50
    elif "metric" in cmd or "med" in cmd:
         try:
            val = int(cmd.split()[-1])
            route.med = val
            route.log(f"    -> Set MED to {val}")
         except:
             pass
    
    # set as-path prepend 65000
    elif "as-path prepend" in cmd:
        parts = cmd.split()
        to_prepend = []
        for p in parts:
             if p.isdigit():
                 to_prepend.append(int(p))
        
        # Prepend logic
        route.as_path = to_prepend + route.as_path
        route.log(f"    -> Prepended AS-Path: {to_prepend}")
