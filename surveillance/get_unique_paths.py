import os, sys

def unique_paths(input_file, output_file):
    
    if not os.path.exists(input_file):
        print("No File Found")
        sys.exit(1)
    
    seen = set()
    unique_list = []
    with open(input_file, "r", encoding="utf-8") as f:
        for line in f:
            path = line.strip()
            if not path: continue

            if path.startswith('"') and path.endswith('"'):
                if path not in seen:
                    seen.add(path)
                    unique_list.append(path)
    
    if output_file:
        with open(output_file, "w", encoding="utf-8") as f:
            for item in unique_list:
                f.write(item + "\n")
    
    return unique_list

if __name__ == "__main__":
    input = "paths.txt"
    output = "paths_unique.txt"

    paths = unique_paths(input, output)

    try:
        os.remove(input)
        os.replace(output, input)
    except Exception as e:
        print("File operation failed, but unqie paths were created:", str(e))

    print("Unique paths from list: ")
    for path in paths: print(path)
