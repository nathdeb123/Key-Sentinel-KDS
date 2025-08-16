import tkinter as tk
import random
from tkinter import messagebox

COLORS = ["red", "green", "blue", "yellow"]
COLOR_MAP = {
    "red":   {"normal": "#e53935", "flash": "#ffcdd2"},
    "green": {"normal": "#43a047", "flash": "#c8e6c9"},
    "blue":  {"normal": "#1e88e5", "flash": "#bbdefb"},
    "yellow":{"normal": "#fdd835", "flash": "#fff9c4"},
}

class ButtonRememberGame:
    def __init__(self, root):
        self.root = root
        self.root.title("🎮 Button Remember – 4 Round Game")
        self.root.configure(bg="#101418")

        self.sequence = []
        self.user_index = 0
        self.round_num = 0
        self.max_rounds = 4
        self.playing_back = False
        self.game_active = False

        self.status = tk.Label(self.root, text="Press START",
                               fg="white", bg="#101418", font=("Arial", 14))
        self.status.grid(row=0, column=0, columnspan=2, pady=10)

        # Buttons
        self.buttons = {}
        grid = [("red", 1, 0), ("green", 1, 1), ("blue", 2, 0), ("yellow", 2, 1)]
        for color, r, c in grid:
            btn = tk.Button(self.root, bg=COLOR_MAP[color]["normal"],
                            width=12, height=6,
                            command=lambda col=color: self.user_press(col))
            btn.grid(row=r, column=c, padx=10, pady=10)
            self.buttons[color] = btn

        # Control
        self.start_btn = tk.Button(self.root, text="START", font=("Arial", 12, "bold"),
                                   command=self.start_game, bg="lightgreen")
        self.start_btn.grid(row=3, column=0, columnspan=2, pady=10)

    def start_game(self):
        self.sequence = []
        self.round_num = 0
        self.user_index = 0
        self.game_active = True
        self.status.config(text="Memorize the sequence…")
        self.next_round()

    def next_round(self):
        if self.round_num >= self.max_rounds:
            self.success_message()
            return

        self.round_num += 1
        self.status.config(text=f"Round {self.round_num}")
        self.sequence.append(random.choice(COLORS))
        self.user_index = 0
        self.play_sequence()

    def play_sequence(self):
        self.playing_back = True
        delay = 600
        t = 0
        for color in self.sequence:
            self.root.after(t, lambda col=color: self.flash(col))
            t += delay
        self.root.after(t, self.enable_input)

    def enable_input(self):
        self.playing_back = False
        self.status.config(text="Your turn! Repeat it.")

    def user_press(self, color):
        if not self.game_active or self.playing_back:
            return

        self.flash(color, duration=200)

        if color == self.sequence[self.user_index]:
            self.user_index += 1
            if self.user_index == len(self.sequence):
                if self.round_num < self.max_rounds:
                    self.root.after(800, self.next_round)
                else:
                    self.success_message()
        else:
            self.status.config(text="❌ Wrong! Press START to try again.")
            self.game_active = False

    def flash(self, color, duration=400):
        btn = self.buttons[color]
        btn.config(bg=COLOR_MAP[color]["flash"])
        self.root.after(duration, lambda: btn.config(bg=COLOR_MAP[color]["normal"]))

    def success_message(self):
        self.game_active = False
        messagebox.showinfo("🎉 Success", "Congratulations! \n For Activation key you have to put your 'Credentials' side by side in capslock  like (If -Name : Abc , DOB: 1999-9-9,  Act-Key: ABC1999-9-9)")
        self.status.config(text="Game Finished – Press START to play again.")

if __name__ == "__main__":
    root = tk.Tk()
    game = ButtonRememberGame(root)
    root.mainloop()
