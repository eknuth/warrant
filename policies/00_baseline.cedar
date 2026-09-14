// The W5 policy set is deliberately empty.
//
// Cedar denies when no permit matches, so shipping no permit is the safe
// default: nothing is authorized until W7 writes the policies that say what is.
// This file exists so the loader has a file to read and so the empty state is
// visible rather than implied by an empty directory.
