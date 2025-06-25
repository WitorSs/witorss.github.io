---
title: "Basic Password Strength Checker in Python"
author: Vitorx
categories: [Personal Projects]
tags: [Python, Tkinter, Password Strength Checker, Password Validation, Password Security]
render_with_liquid: false
img_path: /images/password-strength
image:
  path: /images/password-strength/password.png
---

In this post, I show how I created a simple Password Strength Checker in Python using Tkinter. I explain the logic to evaluate password strength and how to build a simple, functional interface with a progress bar and a button to show/hide the password. A practical project ideal for those starting to program in Python.

---

## 🧠 What Is a Password Strength Checker?

A password strength checker helps users create secure passwords by evaluating their strength based on predefined criteria. It typically checks for:

- Minimum length

- Uppercase and lowercase letters

- Numbers

- Special characters

## 🔧 Tools Used

- Python 3.13.5

- Tkinter (built-in GUI library in Python)

- Ttk for modern-looking widgets

- re module (regular expressions for pattern checking)

## 💡 How It Works

This app analyzes your password in real time and displays its strength visually and interactively. Below, I’ll walk through each part of the interface using images.

### Application Interface
When the program starts, it opens a simple and clean window with a title, a password input field, a strength indicator, and a tips area.

![Desktop View](/images/password-strength/interface.jpg){: width="972" height="589" }
_Interface_

### ⛔ Typing a Weak Password
As you start typing a simple password (abc123), the app detects that it lacks key elements like uppercase letters and special characters.

- The strength is labeled "Weak"

- The text appears in red

- The progress bar fills partially

- The app gives tips to improve your password

![Desktop View](/images/password-strength/weak.jpg){: width="972" height="589" }
_Weak Password_

### ⚠️ Typing a Medium Password

When your password meets some but not all criteria (e.g., Abc12345), the app shows:

- Strength: "Medium"

- Text in orange

- A longer progress bar

- Fewer improvement tips

![Desktop View](/images/password-strength/medium.jpg){: width="972" height="589" }
_Medium Password_

### ✅ Typing a Strong Password

When the password satisfies all conditions (length, upper/lowercase, numbers, symbols), it is marked as "Strong".

- Green label and progress bar

- No tips are shown — just a message: "Strong password!

![Desktop View](/images/password-strength/strong.jpg){: width="972" height="589" }
_Strong password_

## ✔️ Conclusion

Password security remains a critical component of modern cybersecurity practices, especially considering the prevalence of credential stuffing, brute-force attacks, and poor user password hygiene. This project demonstrates how simple tools can be used to promote secure password creation by implementing basic validation criteria — such as length, character variety, and complexity — commonly recommended by NIST and OWASP guidelines.

By combining Python with Tkinter, this Password Strength Checker serves not only as an educational tool for aspiring developers, but also as a foundational step toward building more advanced user authentication mechanisms. Projects like this reinforce the principle of security by design, encouraging the integration of usability and protection at the user input level.


## Here is the code

```py
import tkinter as tk
from tkinter import ttk
import re

class PasswordCheckerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Strength Checker")
        self.root.geometry("450x300")
        self.root.configure(bg="#2e3440")
        self.root.resizable(False, False)

        # Fonte
        self.fonte_titulo = ("Helvetica", 16, "bold")
        self.fonte_normal = ("Helvetica", 12)
        self.fonte_dica = ("Helvetica", 10, "italic")

        # Título
        self.titulo = tk.Label(root, text="Verificador de Força de Senha", 
                               font=self.fonte_titulo, bg="#2e3440", fg="#d8dee9")
        self.titulo.pack(pady=(20,10))

        # Frame para entrada e botão mostrar senha
        self.frame_entrada = tk.Frame(root, bg="#2e3440")
        self.frame_entrada.pack(pady=5)

        # Campo de senha
        self.senha_var = tk.StringVar()
        self.entrada = ttk.Entry(self.frame_entrada, width=30, font=self.fonte_normal, textvariable=self.senha_var, show="*")
        self.entrada.pack(side="left", padx=(0,5))
        self.entrada.bind("<KeyRelease>", self.verificar_forca_senha)

        # Botão mostrar/ocultar senha
        self.mostrar = False
        self.btn_mostrar = ttk.Button(self.frame_entrada, text="👁️", width=3, command=self.toggle_mostrar_senha)
        self.btn_mostrar.pack(side="left")

        # Label resultado
        self.resultado = tk.Label(root, text="", font=self.fonte_normal, bg="#2e3440", fg="#d8dee9")
        self.resultado.pack(pady=10)

        # Barra de progresso
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("green.Horizontal.TProgressbar", foreground='#a3be8c', background='#a3be8c')
        style.configure("orange.Horizontal.TProgressbar", foreground='#ebcb8b', background='#ebcb8b')
        style.configure("red.Horizontal.TProgressbar", foreground='#bf616a', background='#bf616a')

        self.barra = ttk.Progressbar(root, orient="horizontal", length=300, mode="determinate")
        self.barra.pack(pady=10)

        # Label dicas
        self.dicas = tk.Label(root, text="", font=self.fonte_dica, bg="#2e3440", fg="#88c0d0", wraplength=400, justify="center")
        self.dicas.pack(pady=10)

    def toggle_mostrar_senha(self):
        if self.mostrar:
            self.entrada.config(show="*")
            self.mostrar = False
            self.btn_mostrar.config(text="👁️")
        else:
            self.entrada.config(show="")
            self.mostrar = True
            self.btn_mostrar.config(text="🙈")

    def calcular_forca(self, senha):
        pontuacao = 0
        dicas = []
        if len(senha) >= 8:
            pontuacao += 1
        else:
            dicas.append("Use ao menos 8 caracteres.")

        if re.search(r"[A-Z]", senha):
            pontuacao += 1
        else:
            dicas.append("Inclua letras maiúsculas.")

        if re.search(r"[a-z]", senha):
            pontuacao += 1
        else:
            dicas.append("Inclua letras minúsculas.")

        if re.search(r"\d", senha):
            pontuacao += 1
        else:
            dicas.append("Inclua números.")

        if re.search(r"[!@#$%^&*(),.?\":{}|<>]", senha):
            pontuacao += 1
        else:
            dicas.append("Inclua caracteres especiais (!@#$ etc).")

        if pontuacao <= 2:
            return "Fraca", dicas
        elif pontuacao in (3, 4):
            return "Média", dicas
        else:
            return "Forte", dicas

    def verificar_forca_senha(self, event=None):
        senha = self.senha_var.get()
        forca, dicas = self.calcular_forca(senha)
        cores = {"Fraca": "#bf616a", "Média": "#ebcb8b", "Forte": "#a3be8c"}
        self.resultado.config(text=f"Força: {forca}", fg=cores[forca])

        # Atualiza barra de progresso
        valor = {"Fraca": 40, "Média": 70, "Forte": 100}
        self.barra['value'] = valor[forca]
        style_name = {
            "Fraca": "red.Horizontal.TProgressbar",
            "Média": "orange.Horizontal.TProgressbar",
            "Forte": "green.Horizontal.TProgressbar"
        }
        self.barra.config(style=style_name[forca])

        # Atualiza dicas
        if forca != "Forte":
            texto_dicas = "Dicas para melhorar:\n" + "\n".join(dicas)
        else:
            texto_dicas = "Senha forte! 🎉"
        self.dicas.config(text=texto_dicas)


if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordCheckerApp(root)
    root.mainloop()

```
