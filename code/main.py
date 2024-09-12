from flask import Flask, request
from flask import render_template
import os
from hashlib import sha1 as sha
import json
import base64
import hmac
import datetime
import time

app = Flask(__name__)

# 配置环境变量OSS_ACCESS_KEY_ID。
# access_key_id = os.environ.get('OSS_ACCESS_KEY_ID')
# 配置环境变量OSS_ACCESS_KEY_SECRET。
# access_key_secret = os.environ.get('OSS_ACCESS_KEY_SECRET')
# 将${your-bucket}替换为Bucket名称。
# bucket = '<your-bucket>'
# # host的格式为bucketname.endpoint。将<your-bucket>替换为Bucket名称。将<your-endpoint>替换为OSS Endpoint，例如oss-cn-hangzhou.aliyuncs.com。
# host = 'https://<your-bucket>.<your-endpoint>'

bucket_name = os.environ.get('BUCKET_NAME')
region_id = os.environ.get('REGION_ID')
# host的格式为bucketname.endpoint。将{bucket_name}为Bucket名称,{region_id}为oss的region。
host = f"https://{bucket_name}.oss-{region_id}.aliyuncs.com"

# 指定上传到OSS的文件前缀。
upload_dir = 'user-dir-prefix/'
# 指定过期时间，单位为秒。
expire_time = 3600


def generate_expiration(seconds):
    """
    通过指定有效的时长（秒）生成过期时间。
    :param seconds: 有效时长（秒）。
    :return: ISO8601 时间字符串，如："2014-12-01T12:00:00.000Z"。
    """
    now = int(time.time())
    expiration_time = now + seconds
    gmt = datetime.datetime.utcfromtimestamp(expiration_time).isoformat()
    gmt += 'Z'
    return gmt


def generate_signature(access_key_secret, expiration, conditions, policy_extra_props=None):
    """
    生成签名字符串Signature。
    :param access_key_secret: 有权限访问目标Bucket的AccessKeySecret。
    :param expiration: 签名过期时间，按照ISO8601标准表示，并需要使用UTC时间，格式为yyyy-MM-ddTHH:mm:ssZ。示例值："2014-12-01T12:00:00.000Z"。
    :param conditions: 策略条件，用于限制上传表单时允许设置的值。详细参考：https://help.aliyun.com/zh/oss/developer-reference/postobject 。
    :param policy_extra_props: 额外的policy参数，后续如果policy新增参数支持，可以在通过dict传入额外的参数。
    :return: signature，签名字符串。
    """
    policy_dict = {
        'expiration': expiration,
        'conditions': conditions
    }
    if policy_extra_props is not None:
        policy_dict.update(policy_extra_props)
    policy = json.dumps(policy_dict).strip()
    policy_encode = base64.b64encode(policy.encode())
    h = hmac.new(access_key_secret.encode(), policy_encode, sha)
    sign_result = base64.b64encode(h.digest()).strip()
    return sign_result.decode()


@app.route("/")
def hello_world():
    return render_template('index.html')


@app.route('/get_post_signature_for_oss_upload', methods=['GET'])
def generate_upload_params():
    # 函数计算通过角色扮演获得临时token，避免硬编码ak。
    access_key_id=request.headers.get('x-fc-access-key-id')
    access_key_secret=request.headers.get('x-fc-access-key-secret')
    security_token=request.headers.get('x-fc-security-token')
    policy = {
        # 有效期。
        "expiration": generate_expiration(expire_time),
        # 约束条件，参考：https://help.aliyun.com/zh/oss/developer-reference/postobject。
        "conditions": [
            # 未指定success_action_redirect时，上传成功后的返回状态码，默认为 204。
            ["eq", "$success_action_status", "200"],
            # 表单域的值必须以指定前缀开始。例如指定key的值以user/user1开始，则可以写为["starts-with", "$key", "user/user1"]。
            ["starts-with", "$key", upload_dir],
            # 限制上传Object的最小和最大允许大小，单位为字节。
            # ["content-length-range", 1, 1000000],
            # 限制上传的文件为指定的图片类型
            # ["in", "$content-type", ["image/jpg", "image/png"]]
        ]
    }
    signature = generate_signature(access_key_secret, policy.get('expiration'), policy.get('conditions'))
    response = {
        'policy': base64.b64encode(json.dumps(policy).encode('utf-8')).decode(),
        'ossAccessKeyId': access_key_id,
        'securityToken': security_token,
        'signature': signature,
        'host': host,
        'dir': upload_dir
        # 可以在这里再自行追加其他参数
    }
    return json.dumps(response)


app.run(host="0.0.0.0", port=8000)
