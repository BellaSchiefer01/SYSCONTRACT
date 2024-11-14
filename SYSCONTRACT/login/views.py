from django.shortcuts import render

# Create your views here.
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import UserCreationForm
from django.contrib import messages

from django.http import JsonResponse, HttpResponse
import requests


def login_view(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        data = {
            'username': username,
            'password':  password,
        }
        response = requests.post('http://localhost:8000/login', data=data)

        if response.status_code == 200:
            data = response.json()
            access_token = data.get('access_token')

            # Definindo o cookie no backend
            response = redirect('/dashboard')
            response.set_cookie(
                'access_token',
                access_token,
                max_age=3600,
                secure=False,   
                httponly=True,
                samesite='Strict' 
            )

            return response
        else:
            messages.error(request, 'Usuário ou senha inválidos.')

    # Verifica se o usuário está logado, se sim, redireciona para o dashboard
    access_token = request.COOKIES.get('access_token')
    if access_token:
        response = requests.get('http://localhost:8000/verify_token/',
        headers={'Authorization': f'Bearer {access_token}'})
        if response.status_code == 200:
            return redirect('/dashboard/')
        
        response = redirect('/login/')
        response.delete_cookie('access_token')
        return response

    return render(request, 'login/login.html')

# View para o registro
def register_view(request):

    # Verifica se o usuário está logado
    access_token = request.COOKIES.get('access_token')
    if access_token:
        response = requests.get('http://localhost:8000/verify_token/',
        headers={'Authorization': f'Bearer {access_token}'})
        if response.status_code != 200:
            response = redirect('/login/')
            response.delete_cookie('access_token')
            return response
    else:
        response = redirect('/login/')
        response.delete_cookie('access_token')
        return response


    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, 'Conta criada com sucesso! Agora faça login.')
            return redirect('login')
    else:
        form = UserCreationForm()
    
    return render(request, 'login/register.html', {'form': form})

# View para fazer logout
def logout_view(request):
    logout(request)
    return redirect('login')  

# View para o dashboard, requer login
@login_required
def dashboard_view(request):
    return render(request, 'login/dashboard.html')  