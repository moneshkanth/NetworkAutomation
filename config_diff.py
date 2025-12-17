import difflib

def generate_diff(old_text, new_text):
    """
    Compares two strings and returns a unified diff.
    
    Args:
        old_text (str): The original configuration.
        new_text (str): The new configuration.
        
    Returns:
        str: A single string containing the unified diff.
    """
    # Split into lines for difflib
    old_lines = old_text.splitlines()
    new_lines = new_text.splitlines()
    
    diff = difflib.unified_diff(
        old_lines, 
        new_lines, 
        fromfile='Old Config', 
        tofile='New Config',
        lineterm=''
    )
    
    # Return as a single string joined by newlines
    return '\n'.join(diff)

def generate_html_diff(old_text, new_text):
    """
    Compares two strings and returns an HTML side-by-side diff.
    
    Args:
        old_text (str): The original configuration.
        new_text (str): The new configuration.
        
    Returns:
        str: HTML content representing the side-by-side diff table.
    """
    old_lines = old_text.splitlines()
    new_lines = new_text.splitlines()
    
    differ = difflib.HtmlDiff()
    return differ.make_file(old_lines, new_lines, fromdesc='Old Config', todesc='New Config')
