from ery4z_toolbox import profile


@profile
def main():
    my_funct(100)


def my_funct(n):
    print(n)
    if n != 0:
        return my_funct(n - 1)
    else:
        return 0


main()
