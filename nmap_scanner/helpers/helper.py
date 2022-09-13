def compare_old_new(old, new):
    old_set = set(old)
    new_set = set(new)

    return list(new_set - old_set), list(old_set - new_set)

def build_dictionary(data):
    dictionary = {}
    for row in data:
        hostname, old_ports = row[0], row[1]
        dictionary[hostname] = old_ports.split(",")
    return dictionary