import os


def test_mutate_file():
    path = os.path.realpath(__file__)
    parent = path.split("/tests/")[0]
    src_dir = os.path.join(parent, "src")

    with open(os.path.join(src_dir, "file_to_mutate.py")) as f:
        lines = f.readlines()

    for l in lines:
        if "num_mutations = " in l:
            index = lines.index(l)
            num_mutations = int(l.split()[-1]) + 1
            lines[index] = f"num_mutations = {num_mutations}\n"

    with open(os.path.join(src_dir, "file_to_mutate.py"), "w") as f:
        f.write("".join(lines))

    assert True
