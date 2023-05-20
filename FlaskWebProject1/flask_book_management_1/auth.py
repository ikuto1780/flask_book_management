"""
ログイン処理などを行う
"""

from datetime import datetime
import functools
from flask import(
    Blueprint, flash, g, redirect, render_template, request, session, url_for
    )
from werkzeug.security import check_password_hash, generate_password_hash
from flask_book_management_1.db import get_db

bp = Blueprint('auth', __name__, url_prefix = '/auth')


@bp.route('/create_user', methods=('GET', 'POST'))
def create_user():
    """
    GET ：ユーザー登録画面に遷移
    POST：ユーザー登録処理を実施
    """
    if request.method == 'GET':
        # ユーザー登録画面に遷移
        return render_template('auth/create_user.html',
                               title='ユーザー登録',
                               year=datetime.now().year)


    # ユーザー登録処理

    # 登録フォームから送られてきた、ユーザー名とパスワードを取得
    username = request.form['username']
    password = request.form['password']

    # DBと接続
    db = get_db()

    # エラーチェック
    error_message = None

    if not username:
        error_message = 'ユーザー名の入力は必須です'
    elif not password:
        error_message = 'パスワードの入力は必須です'
    elif db.execute('SELECT id FROM user WHERE username = ?', (username,)).fetchone() is not None:
        error_message = 'ユーザー名 {} はすでに使用されています'.format(username)


    if error_message is not None:
        # エラーがあれば、それを画面に表示させる
        flash(error_message, category='alert alert-danger')
        return redirect(url_for('auth.create_user'))


    # エラーがなければテーブルに登録する
    # パスワードはハッシュ化したものを登録
    db.execute(
        'INSERT INTO user (username, password) VALUES (?, ?)',
        (username, generate_password_hash(password))
    )
    db.commit()

    # ログイン画面へ遷移
    flash('ユーザー登録が完了しました。登録した内容でログインしてください', category='alert alert-info')
    return redirect(url_for('auth.login'))


@bp.route('/login', methods = ('GET', 'POST'))
def login():
    """
    GET：ユーザ登録画面に遷移
    POST：ユーザ登録処理を実施
    """
    if request.method == 'GET':
        #ログイン画面に遷移
        return render_template('auth/login.html',
                               title = 'ログイン',
                               year = datetime.now().year)

    #ログイン処理
    #ログインフォームから送られてきたユーザ名、パスワードを取得
    username = request.form['username']
    password = request.form['password']

    #DBと接続
    db = get_db()

    #ユーザ名とパスワードのチェック
    error_message = None
    
    user = db.execute(
        'SELECT * FROM user WHERE username = ?', (username,)
        ).fetchone()

    if user is None:
        error_message = 'ユーザ名が正しくありません'
    elif not check_password_hash(user['password'],password):
        error_message = 'パスワードが正しくありません'

    if error_message is not None:
        #エラーがあればそれを表示したうえでログイン画面へ遷移
        flash(error_message, category = 'alert alert-danger')
        return redirect(url_for('auth.login'))

    #エラーが無ければ、セッションにユーザIDを追加してインデックスページへ遷移
    session.clear()
    session['user_id'] = user['id']
    flash('ログイン名：{} さん'.format(username), category='alert alert-info')
    return redirect(url_for('home'))


@bp.route('/logout')
def logout():
    """ログアウトする"""
    session.clear()
    flash('ログアウトしました', category = 'alert alert-info')
    return redirect(url_for('home'))



@bp.before_app_request
#どのURLが指定されても実行される関数とする
def load_logged_in_user():
    """
    どのURLが要求されても、ビュー関数の前で実行される関数
    ログインしているか確認し、ログインされていればユーザ情報を取得する
    """
    user_id = session.get('user_id')

    if user_id is None:
        g.user = None
    else:
        db = get_db()
        g.user = db.execute(
            'SELECT * FROM user WHERE id = ?', (user_id,)
            ).fetchone()

def login_required(view):
    """
    ユーザがログインされているかどうかをチェックし、
    そうでなければログインページにリダイレクト
    """
    #毎回ログイン判定を行いログイン画面に飛ばすという処理を実装するのは面倒なので、
    #関数をラップ(包む)する関数を定義し、先の機能を簡単に他の関数へ追加できるようにする
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            #遷移先の画面に表示する任意の文字
            #Bootstrapのclassの1つで、alert alert-warningをclassに指定すると、黄色い文字でワーニングを表すことができる
            flash('ログインをしてから操作してください。', category = 'alert alert-warning')
            return redirect(url_for('auth.login'))

        return view(**kwargs)

    return wrapped_view
