import tkinter as tk, os, customtkinter as ck, string, random, zipfile, subprocess,webbrowser
from cryptography.fernet import Fernet
from tkinter import filedialog, messagebox
from datetime import datetime
from tkinter import ttk
from PIL import ImageTk, Image
import matplotlib.pyplot as plt


def visualize_strength():
    password = entry.get()
    score, _, _ = check_password_strength(password)
    categories = ['Length', 'Uppercase', 'Lowercase', 'Digits', 'Special Characters']
    scores = [0 if len(password) < 8 else 1, any(char.isupper() for char in password), 
              any(char.islower() for char in password), any(char.isdigit() for char in password), 
              any(char in string.punctuation for char in password)]
    
    plt.bar(categories, scores, color=['red' if s == 0 else 'green' for s in scores])
    plt.title('Password Strength')
    plt.xlabel('Criteria')
    plt.ylabel('Pass/Fail')
    plt.yticks([0, 1])
    plt.show()

def start_tutorial():
    tutorial_steps = [
        "Step 1: Enter a password and check its strength using the 'Password Health' button.",
        "Step 2: Encrypt the password by clicking the 'Encrypt' button.",
        "Step 3: Decrypt the password by selecting the appropriate key file and encrypted file, then click 'Decrypt'.",
        "Step 4: Generate a random password using the 'Generate' button.",
        "Step 5: Send a file by clicking the 'Send By Email' button.",
        "Step 6: If you need help, click on the 'Tutorial' button again."
    ]

    for step in tutorial_steps:
        messagebox.showinfo("Tutorial", step)

def check_password_strength(password):
    """
    This function checks the strength of a password based on various criteria.

    Args:
        password: The password to be checked.

    Returns:
        A tuple containing a score (int) and a message (str) describing the password strength.
    """
    score = 0
    messages = []

    if len(password) < 8:
        score += 1
        messages.append("Password is too short.")
    else:
        score += 1

    # Check for uppercase characters
    if any(char.isupper() for char in password):
        score += 1
    else:
        messages.append("Password should contain uppercase characters.")

    # Check for lowercase characters
    if any(char.islower() for char in password):
        score += 1
    else:
        messages.append("Password should contain lowercase characters.")

    # Check for digits
    if any(char.isdigit() for char in password):
        score += 1
    else:
        messages.append("Password should contain digits.")

    # Check for special characters
    if any(char in string.punctuation for char in password):
        score += 1
    else:
        messages.append("Password should contain special characters.")

    # Adjust score based on password length
    if len(password) >= 12:
        score += 1
    elif len(password) >= 10:
        score += 0.5

    strength = "Weak"
    if score >= 4:
        strength = "Moderate"
    if score >= 5:
        strength = "Strong"

    return score, '\n'.join(messages), strength


def encrypt_password():
    timestamp = datetime.now().strftime("%Y-%m-%d-%H%M%S")
    key_file = os.getcwd() + "/" + timestamp + ".key"
    encrypt_file = os.getcwd() + "/" + timestamp + ".txt"
    zip_file_name = timestamp + ".zip"
    try:
        with open(key_file, "rb") as f:
            key = f.read()
    except FileNotFoundError:
        key = Fernet.generate_key()
        with open(key_file, "wb") as f:
            f.write(key)

    f = Fernet(key)

    password = entry.get().encode()
    encrypted_password = f.encrypt(password)
    with open(encrypt_file,'wb') as e:
        e.write(encrypted_password)

    files_to_zip = [key_file, encrypt_file]

    with zipfile.ZipFile(zip_file_name, 'w') as zip_file:
        for file in files_to_zip:
            zip_file.write(file, os.path.basename(file)) 

def decrypt_password():
    index = combo.current()
    paths = [os.path.join(os.getcwd() + '/', item) for item in combo['values']]
    path = paths[index]
    index2 = combo2.current()
    paths2 = [os.path.join(os.getcwd() + '/', item) for item in combo2['values']]
    path2 = paths2[index2]

    with open(path, "rb") as f:
        key = f.read()
    f = Fernet(key)

    try:
        with open(path2,'r') as file:
            first_line = file.readline()
        encrypted_password = first_line
        decrypted_password = f.decrypt(encrypted_password)
        entry.delete(0,'end')
        entry.insert(0,f'{decrypted_password.decode()}')
    except:
        entry.delete(0,'end')
        entry.insert(0,'Invalid Token')

def main_file_list(event):
    dir_path = os.getcwd()
    file_list = os.listdir(dir_path)
    combo['values'] = []
    for file_name in file_list:
        if file_name.endswith('.key'):
            combo['values'] = (*combo['values'], file_name)

def main_file_list2(event):
    dir_path = os.getcwd()
    file_list = os.listdir(dir_path)
    combo2['values'] = []
    for file_name in file_list:
        if file_name.endswith('.txt'):
            combo2['values'] = (*combo2['values'], file_name)

def generate_password():
    chars = string.ascii_letters + string.digits + string.punctuation
    
    password = ''.join(random.choice(chars) for _ in range(int(combo3.get())))
   
    entry.delete(0,'end')
    entry.insert(0,password)

def password_health_report():
  password = entry.get()
  score, message, strength = check_password_strength(password)

  report_window = tk.Tk()
  report_window.title('Password Health Report')
  width = 300
  height = 150
  screen_width = report_window.winfo_screenwidth()
  screen_height = report_window.winfo_screenheight()
  x = (screen_width / 2) - (width / 2)
  y = (screen_height / 2) - (height / 2)
  report_window.geometry("%dx%d+%d+%d" % (width, height, x, y))
  report_window.resizable(0, 0)

  report_label = tk.Label(report_window, text=f"Strength: {strength}", font=("Arial", 12))
  report_label.pack(pady=10)

  message_label = tk.Label(report_window, text=message, font=("Arial", 10, "italic"))
  message_label.pack()

  report_window.mainloop()
  
import os

def send_file():
  file_path = filedialog.askopenfilename(filetypes=[("Zip Files", "*.zip"), ("All", "*.*")])
  if file_path:
    if os.path.isfile(file_path):  
      os.startfile(file_path)  
    else:
      messagebox.showerror("Error", "Please select a valid file.")
  else:
    messagebox.showerror("Error", "Please select a file first.")


def copy_to_clipboard(event):
    window.clipboard_clear()
    widget = event.widget
    if widget.get():
        widget.selection_range(0, tk.END)
        widget.clipboard_append(widget.selection_get())

def clear_entry(event):
    entry.delete(0,'end')

def clear_combo(event):
    combo3.delete(0,'end')

 # ALL GUI STUFF
window = tk.Tk()
window.title('AuthGuard')
width = 700
height = 450
screen_width = window.winfo_screenwidth()
screen_height = window.winfo_screenheight()
x = (screen_width/2) - (width/2)
y = (screen_height/4) - (height/4)
window.geometry("%dx%d+%d+%d" % (width, height, x, y))
window.resizable(0, 0)
window.configure(background='#a4a8ab')

my_font = ("Arial", 16, "bold")

canvas = tk.Canvas(window, width=700, height=450, highlightthickness=0)
canvas.pack()

image = Image.open("resources/bg.png")
photo = ImageTk.PhotoImage(image)

canvas.create_image(0, 0, anchor=tk.NW, image=photo)

frame = ck.CTkFrame(window, width=250, height=250, fg_color='#5F6082', corner_radius=30,bg_color='#313246', border_width=5)
frame.place(relx=0.62,y=10)

frame2 = ck.CTkFrame(window, width=170, height=170, fg_color='#5F6082', corner_radius=30,bg_color='#313246', border_width=5)
frame2.place(relx=0.735,y=261)

label = ck.CTkLabel(frame, text="Enter a password", text_color=('black'), font=my_font)
label.place(relx=0.5, y=25, anchor=tk.CENTER)

entry = ttk.Entry(frame, width=15)
entry.place(relx=0.5, y=50, anchor=tk.CENTER)

encrypt_img = ck.CTkImage(light_image=Image.open("resources/encrypt.png"),size=(32,32))
decrypt_img = ck.CTkImage(light_image=Image.open("resources/decrypt.png"),size=(32,32))
generate_img = ck.CTkImage(light_image=Image.open("resources/generate.png"),size=(20,20))
send_img = ck.CTkImage(light_image=Image.open("resources/send.png"),size=(20,20))
exit_img = ck.CTkImage(light_image=Image.open("resources/exit.png"),size=(20,20))

health_button = ck.CTkButton(window, text="Password Health", height=40, fg_color='#806d5f', border_width=2, border_color='#313246', hover_color='#f7ca18', command=password_health_report)
health_button.place(relx=0.15, rely=0.20, anchor=tk.CENTER)
tutorial_button = ck.CTkButton(window, text="Tutorial", height=40, fg_color='#806d5f', border_width=2, border_color='#313246', hover_color='#f7ca18', command=start_tutorial)
tutorial_button.place(relx=0.15, rely=0.35, anchor=tk.CENTER)
strength_button = ck.CTkButton(window, text="Visualize Strength", height=40, fg_color='#806d5f', border_width=2, border_color='#313246', hover_color='#f7ca18', command=visualize_strength)
strength_button.place(relx=0.15, rely=0.5, anchor=tk.CENTER)

encrypt_button = ck.CTkButton(frame, text="Encrypt", height=40, fg_color='#806d5f', border_width=2, border_color='#313246', hover_color='#f03e34', image=encrypt_img, command=encrypt_password)
encrypt_button.place(relx=0.5, y=90, anchor=tk.CENTER)
decrypt_button = ck.CTkButton(frame, text="Decrypt",height=40, fg_color='#806d5f', border_width=2, border_color='#313246', hover_color='#01aaed', image=decrypt_img, command=decrypt_password)
decrypt_button.place(relx=0.5, y=215, anchor=tk.CENTER)
generate_button = ck.CTkButton(frame2, text="Generate",width=100,height=40, fg_color='#806d5f', border_width=2, border_color='#313246', hover_color='grey', image=generate_img,compound=tk.RIGHT, command=generate_password)
generate_button.place(relx=0.35, y=40, anchor=tk.CENTER)
send_button = ck.CTkButton(frame2, text="Send By\n Email",width=100,height=40, fg_color='#806d5f', border_width=2, border_color='#313246', hover_color='#95c73c', image=send_img,compound=tk.RIGHT, command=send_file)
send_button.place(relx=0.5, y=90, anchor=tk.CENTER)
exit_button = ck.CTkButton(frame2, text="Exit",width=80,height=30, fg_color='#806d5f', border_width=2, border_color='#313246', hover_color='#222534', image=exit_img,compound=tk.RIGHT, command=lambda: window.destroy())
exit_button.place(relx=0.30, y=140, anchor=tk.CENTER)
style = ttk.Style()
style.theme_use('classic')
style.configure('TCombobox', bordercolor='white', lightcolor='white')

combo = ttk.Combobox(frame, style='TCombobox', width=18)
combo.place(relx=0.5, y=145, anchor=tk.CENTER)
combo2 = ttk.Combobox(frame, style='TCombobox', width=18)
combo2.place(relx=0.5, y=175, anchor=tk.CENTER)
options = ['12']
combo3 = ttk.Combobox(frame2, style='TCombobox', width=2, values=options)
combo3.current(0)
combo3.place(relx=0.80, y=40, anchor=tk.CENTER)

combo.bind("<Button-1>", main_file_list)
combo2.bind("<Button-1>", main_file_list2)
combo3.bind("<Button-1>", clear_combo)
entry.bind('<Button-1>', copy_to_clipboard)
window.bind('<Control-x>',clear_entry)

window.mainloop()