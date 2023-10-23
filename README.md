# Self Modifying C
This was an experiment I did on Ubuntu which allowed you to change the code that ran at runtime when a function was called. It is definitely not portable in any regard, and may not even work on the same system with different compilers, or different systems with the same compiler.

# Theory
What the code does is this:
- Every function that is told to be modifiable replaces the first few bytes of its code with something that "calls" a function I set up
- Every function that is told to be modifiable is also put into a table of values, where its address maps to what region of memory should be called
- This region of memory is allocated at run time, and Linux is told to set it as executable
- So, when a function is called, it actually jumps to that block of memory, which can be modified at runtime

The main function provided takes in a Hello World function, changes the address of a string that is pushed when puts is called to another string, and lets the function run on. The result is that another string is printed, without having to do anything sophisticated to call the original function.
