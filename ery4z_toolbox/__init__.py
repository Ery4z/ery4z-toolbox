import cProfile
import io
import pstats

# Empty file


def profile(fnc):
    def inner(*args, **kwargs):

        pr = cProfile.Profile()
        pr.enable()
        retval = fnc(*args, **kwargs)
        pr.disable()
        s = io.StringIO()
        sortby = "cumulative"
        ps = pstats.Stats(pr, stream=s).sort_stats(sortby)
        ps.print_stats()
        print(s.getvalue())
        with open("profile_result.txt", "w") as f:
            f.write(s.getvalue())
        return retval

    return inner
