#!/usr/bin/env python3
'''
This program will first analyze the maze and fill out a two dimensional list with elements
contained within the input file, making note of the start point

The program will then explore neighboring cells from the start location starting with the right cell
by passing the location to a method which will process the cell, and mark it as explored, or maze solved.

The program will make note if there is more than one exploratory juxtaposing cell, and store the cell 
location into a list ordered latest found to earliest found, then note cells explored after this into
a list. If a dead end is hit the location jumps to the location of the top of the list. 
if a jump is made the dead end path is marked with x's by going over explored cells and then wiping the explored
list.

When the program lands on the end cell, it prints out the full path and maze complete.

Every jump the program prints out the entire maze by feeding the multidimensional list into a method which 
will interpret it and print it to stdout. The multidimensional list will actually be a class I create because
python doesn't allow you to initialize a multidimensional array without specific boundaries.

******Note******
This code should actually work with any ASCII maze that contains spaces for open paths, and a S, and E for 
start and ending points. characters representing borders are redundant. 

@version: 1.0a
@author: tak
'''

'''
Main method in which the program starts
'''
def main():
    location = [] #list to hold the location we are at in the maze
    hasNoEnd = True
    
    mazefile = input("What maze do you want solved?: ")
    maze = slurp(mazefile)
    #slightly different than I had planned.
    for y in range(0, len(maze)):
        for x in range(0, len(maze[y])):
            if maze[y][x] == 'S':
                location = [y, x]
            elif maze[y][x] == 'E':
                hasNoEnd = False
    if len(location) == 0:
        raise Exception("No start cell found, check your input file")
    if hasNoEnd:
        raise Exception("Maze has no end, unsolvable.")
    
    tick(maze, location[0], location[1])
    print("\n\n")
    dump(maze)
    
'''
Loads the maze file into a matrix and returns it.

@param mazefile: Location of maze file
'''
def slurp(mazefile):
    infile = open(mazefile, 'r')
    #Split the maze into a matrix.
    maze = [list(row) for row in infile.read().splitlines()] #this line is beautiful. python is definately a powerful language.
    infile.close()
    
    return maze

'''
Prints the loaded maze matrix into a human readable format.

@param maze: Loaded maze matrix.
'''
def dump(maze):
    print('\n'.join(''.join(row) for row in maze)) #I had fun writing this too :P
    
'''
My origional plan had too many if statements :/

Whenever I see more than 5 if statements, i know something is wrong.

Recursive method which solves the maze.

@param maze: the maze matrix
@param y: the y location
@param x: the x location
'''
def tick(maze, y, x):
    dump(maze)
    print("\n")
    if maze[y][x] in (' ', 'S'):
        maze[y][x] = 'x'
        #check right, down, left, up
        if (tick(maze, y, x+1) or tick(maze, y-1, x) or 
            tick(maze, y, x-1) or tick(maze, y+1, x)):
            maze[y][x] = '.'
            return True
    elif maze[y][x] == 'E':
        return True #start peeling back.
    return False
        
'''
Start the main method if this program is run as main.
'''
if __name__ == "__main__":
    main()
    
