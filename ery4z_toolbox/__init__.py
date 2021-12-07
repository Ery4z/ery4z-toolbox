import cProfile
import io
import pstats
import os
import traceback

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
        value = s.getvalue()
        print(value)
        path_to_dir = traceback.extract_stack()
        path_to_dir = os.path.dirname(path_to_dir[-2].filename)
        print(os.path.join(path_to_dir, "profile_result.txt"))
        with open(os.path.join(path_to_dir, "profile_result.txt"), "w") as f:
            f.write(value)
        return retval

    return inner
