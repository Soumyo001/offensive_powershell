import os, sys, platform

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

    if platform.system() == "Windows":
        os.system(f"powershell remove-item -path {input} -force")
        os.system(f"powershell move-item -path {output} -destination {input}")
    elif platform.system() == "Linux":
        os.system(f"rm -f {input}")
        os.system(f"mv {output} {input}")

    print("Unique paths from list: ")
    for path in paths: print(path)
    