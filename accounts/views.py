from django.shortcuts import render,redirect
from django.contrib.auth.models import User  #회원 관리해주는 기능 끌어오기
from django.contrib import auth              #회원 권한관리 기능 끌어오기
from accounts.tokens import account_activation_token
from accounts.forms import SignUpForm
from django.contrib.auth import login
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.encoding import force_bytes, force_text
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode

def signup(request):
    if request.method == 'POST':
        form = SignUpForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.is_active = False
            user.save()

            current_site = get_current_site(request)
            subject = 'Activate Your Albatong-Touch Account!'
            message = render_to_string('account_activation_email.html', {
                'user': user,
                'domain': current_site.domain,
                'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                'token': account_activation_token.make_token(user),
            })
            user.email_user(subject, message)

            return redirect('account_activation_sent')
    else:
        form = SignUpForm()
    return render(request, 'signup.html', {'form': form})



def account_activation_sent(request):
    return render(request, 'account_activation_sent.html')


def activate(request, uidb64, token):
    try:
        uid = force_text(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if user is not None and account_activation_token.check_token(user, token):
        user.is_active = True
        user.profile.email_confirmed = True
        user.save()
        return redirect('home')
    else:
        return render(request, 'account_activation_invalid.html')


def login(request):
    if request.method == 'POST':
        #post 요청이 들어온다면
        username = request.POST['username']
        password = request.POST['password']
        user = auth.authenticate(request, username=username, password=password)
        # 입력받은 아이디와 비밀번호가 데이터베이스에 존재하는지 확인.
        if user is not None: 
            # 데이터 베이스에 회원정보가 존재한다면 로그인 시키고 home으로 돌아가기.
            auth.login(request, user)
            return redirect('home')
        else:
            # 회원정보가 존재하지 않는다면, 에러인자와 함께 login 템플릿으로 돌아가기. 
            return render(request, 'login.html', {'error': 'username or password is incorrect.'})
    else:
        return render(request, 'login.html')

def logout(request):
    auth.logout(request)
    #로그아웃 시키고 홈페이지로 보내기
    return redirect('home')
    