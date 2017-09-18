#!/bin/bash

# Create a new session
tmux -2 new-session -d -s debug

# Create a new window
tmux new-window -t debug:1 -n "Script Window"

# Split the window
tmux split-window -h

# Setup the first pane, run the program
tmux select-pane -t 0
tmux send-keys "python $1.py" C-m

# Setup the second pane, debug
tmux select-pane -t 1
tmux send-keys "sleep 1;gdb -p \`pidof $1\`" C-m

tmux attach-session -t debug
