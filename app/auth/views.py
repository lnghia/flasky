from flask import render_template, redirect, request, url_for, flash, session
from flask_login import login_user, logout_user, login_required, current_user
from . import auth
from ..models import User
from .forms import LoginForm, RegistrationForm, UpdatePasswordForm, SendPasswordRecoveryForm, ResetPasswordForm
from .. import db
from ..email import send_email
from app.utils import generate_token, deserialize_token


@auth.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None and user.verify_password(form.password.data):
            login_user(user, form.remember_me.data)
            return redirect(request.args.get('next') or url_for('main.index'))
        flash('Invalid username or password.')
    return render_template('auth/login.html', form=form)


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('auth.login'))


@auth.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(email=form.email.data,
                    password=form.password.data,
                    username=form.username.data)
        db.session.add(user)
        db.session.commit()
        token = user.generate_confirmation_token()
        send_email(user.email, 'Confirm Your Account - Flasky',
                   'auth/email/confirm', user=user, token=token)
        flash('A confirmation email has been sent to you by email.')
        return redirect(url_for('auth.login'))
    return render_template('auth/register.html', form=form)


@auth.route('/confirm/<token>')
@login_required
def confirm(token):
    if current_user.confirmed:
        return redirect(url_for('main.index'))
    if current_user.confirm(token):
        flash('You have confirmed your account. Thanks!')
    else:
        flash('The confirmation links is invalid or has expired.')
    return redirect(url_for('main.index'))


@auth.before_app_request
def before_request():
    if current_user.is_authenticated and not current_user.confirmed and request.endpoint[:5] != 'auth.':
        return redirect(url_for('auth.unconfirmed'))


@auth.route('/unconfirmed')
def unconfirmed():
    if current_user.is_anonymous or current_user.confirmed:
        redirect(url_for('main.index'))
    return render_template('auth/unconfirmed.html')


@auth.route('/resend_confirmation')
def resend_confirmation():
    token = current_user.generate_confirmation_token()
    send_email(current_user.email, 'confirm your account',
               'auth/email/confirm', user=current_user, token=token)
    flash('A new confirmation email has been sent to your email.')
    return redirect(url_for('auth.login'))


@auth.route('/update_password', methods=['GET', 'POST'])
@login_required
def update_password():
    form = UpdatePasswordForm()
    if form.validate_on_submit():
        if current_user.verify_password(form.password.data):
            current_user.password = form.new_password.data
            db.session.add(current_user)
            db.session.commit()
            flash('Your password has been changed.')
        else:
            flash('Invalid password, enter your password to confirm your change.')
    return render_template('auth/update_password.html', form=form)


@auth.route('/account_recovery', methods=['GET', 'POST'])
def send_account_recovery_email():
    form = SendPasswordRecoveryForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None:
            token = generate_token(user.id)
            send_email(user.email, 'Account Recovery - Flasky',
                       'auth/email/account_recovery', token=token, user_email=user.email)
            return render_template(
                'auth/password_recovery_mail_sent.html', user_email=user.email)
        else:
            flash('There is no account linked to this email.')
    return render_template('auth/send_password_recovery.html', form=form)


@auth.route('/account_recovery_confirm/<token>')
def account_recovery_confirm(token):
    id = deserialize_token(token)
    if id is None:
        flash('Your account recovery link is invalid.')
        return redirect(url_for('auth.send_account_recovery_email'))
    else:
        session['id'] = id
        return redirect(url_for('auth.reset_password'))


@auth.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user = User.query.filter_by(id=session.get('id')).first()
        user.password = form.new_password.data
        db.session.add(user)
        db.session.commit()
        flash('Your account has been recovered, use your new password to log in.')
        return redirect(url_for('auth.login'))
    return render_template('auth/reset_password.html', form=form)
