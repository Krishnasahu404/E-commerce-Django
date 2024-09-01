from django.shortcuts import render,redirect
from django.http import HttpResponse
from accounts.forms import RegistrationForm
from accounts.models import Account
from django.contrib import messages,auth
from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required

#mail verifications
from django.utils.http import urlsafe_base64_encode,urlsafe_base64_decode
from django.utils.encoding import force_bytes
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import EmailMessage

User = get_user_model()
# Create your views here.

def register(request):
    if request.method == 'POST':
        form = RegistrationForm(request.POST)
        if form.is_valid():
            # Extract data from form
            first_name = form.cleaned_data['first_name']
            last_name = form.cleaned_data['last_name']
            phone_number = form.cleaned_data['phone_number']
            email = form.cleaned_data['email']
            password = form.cleaned_data['password']
            username = email.split('@')[0]
            
            # Create user
            user = Account.objects.create_user(
                first_name=first_name,
                last_name=last_name,
                username=username,
                email=email,  # Ensure to set the email
                password=password
            )
            user.phone_number = phone_number
            user.save()
            
            
            #user Activation token and verification mail
            current_site = get_current_site(request)
            mail_subject = 'Please Activate your account'
            message = render_to_string('accounts/account__verification_email.html', {
                'user': user,
                'domain': current_site,
                'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                'token': default_token_generator.make_token(user),
            })
            to_email = email
            send_email = EmailMessage(mail_subject,message,to=[to_email])
            send_email.send()
            
            # messages.success(request,'Check Your mail for verification')
            return redirect(f'/accounts/login/?command=verification&email={email}')


    else:
        form = RegistrationForm()
    
    context = {
        'form': form
    }
    
    return render(request, 'accounts/register.html', context)


def login(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')
        
        print(f"Attempting to login with email: {email}")

        user = auth.authenticate(email=email, password=password)
        
        if user is not None:
            print(f"Authenticated user: {user}")
            auth.login(request, user)
            print('Login successful')
            messages.success(request,'you are logged in')
            return redirect('dashboard')
        else:
            print('Authentication failed')
            messages.error(request, 'Invalid login data')
            return redirect('login')
        
    return render(request, 'accounts/login.html')

@login_required(login_url='login')
def logout(request):
    auth.logout(request)
    messages.success(request,'successfully logout')
    # Redirect to the home page or login page
    return redirect('login') 


def activate(request, uid64, token):
    try:
        uid =urlsafe_base64_decode(uid64).decode()
        user = Account._default_manager.get(pk=uid)
        
    except(TypeError,ValueError,OverflowError,Account.DoesNotExist):
        user=None
        
    if user is not None and default_token_generator.check_token(user,token):
        user.is_active = True
        user.save()
        messages.success(request, "Account activated successfully. You can now log in.")
        return redirect('login') 
    else:
        messages.error(request, "Activation link is invalid or expired.")
        return redirect('home')  #
        
        
@login_required(login_url='login')
def dashboard(request):
        return render(request,'accounts/dashboard.html')
    
def forgotPassword(request):
    if request.method == 'POST':
        email = request.POST.get('email', '').strip()
        
        if Account.objects.filter(email=email).exists():
            user = Account.objects.get(email=email)
            
            # Reset password
            current_site = get_current_site(request)
            mail_subject = 'Reset Your Password'
            message = render_to_string('accounts/reset_password_email.html', {
                'user': user,
                'domain': current_site.domain,
                'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                'token': default_token_generator.make_token(user),
            })
            to_email = email
            send_email = EmailMessage(mail_subject, message, to=[to_email])
            send_email.send()
            
            messages.success(request, "Password reset email has been sent.")
            return redirect('login')
        
        else:
            messages.error(request, 'Account does not exist.')
            return redirect('forgotPassword')
    
    return render(request, 'accounts/forgotPassword.html')

def resetpassword_validate(request,uid64,token):
    try:
        uid =urlsafe_base64_decode(uid64).decode()
        user = Account._default_manager.get(pk=uid)
        
    except(TypeError,ValueError,OverflowError,Account.DoesNotExist):
        user=None
        
    if user is not None and default_token_generator.check_token(user,token):
        request.session['uid']=uid
        messages.success(request,"please reset your passwird")
        return redirect ('resetpassword')
    else:
        messages.error(request,'link has been expire')
        return redirect('login')
        

def resetpassword(request):
    if request.method =='POST':
        password = request.POST['password']
        confirm_password = request.POST['confirm_password']
        
        if password==confirm_password:
            uid = request.session.get('uid')
            user = Account.objects.get(pk=uid)
            user.set_password(password),
            user.save()
            messages.success(request,'PAssword changes successsfully')
            return redirect('login')
        else:
            messages.error(request,'Password does not match')
            return redirect('resetpassword')
    else:
        return render(request,'accounts/resetpassword.html')