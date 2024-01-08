#
# Copyright (c) 2014--2015 Red Hat Inc.
#
# This software is licensed to you under the GNU General Public License,
# version 3 (GPLv3). There is NO WARRANTY for this software, express or
# implied, including the implied warranties of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. You should have received a copy of GPLv3
# along with this software; if not, see http://www.gnu.org/licenses/gpl.txt
#

require 'smart_proxy_openscap/version'

module Proxy::OpenSCAP
  class Plugin < ::Proxy::Plugin
    # General smart proxy configuration parameters:
    plugin :openscap, Proxy::OpenSCAP::VERSION

    # File.expand_path 用于将相对路径转换为绝对路径。
    # __FILE__ 表示当前脚本文件的路径。这个路径是相对于执行时的当前工作目录的。
    # 若當前腳本文件路徑為 "/aaa/bbb/ccc/ddd/eee/myscript.ru", 而你在/aaa/bbb/下執行該腳本, __FILE__ = "ccc/ddd/eee/myscript.ru"    
    # File.expand_path("http_config.ru", File.expand_path("../", __FILE__)) 結果為 '/aaa/bbb/ccc/ddd/eee/http_config.ru'
    http_rackup_path  File.expand_path("http_config.ru", File.expand_path("../", __FILE__))
    https_rackup_path File.expand_path("http_config.ru", File.expand_path("../", __FILE__))

    # Loading and dependencies:

    # Settings related:
    # These parameters can be overridden in plugin settings file. 
    # Setting any of the parameters in default_settings to nil will trigger a validation error.
    default_settings :spooldir => '/var/spool/foreman-proxy/openscap',
                     :openscap_send_log_file => File.join(APP_ROOT, 'logs/openscap-send.log'),
                     :contentdir => File.join(APP_ROOT, 'openscap/content'),
                     :reportsdir => File.join(APP_ROOT, 'openscap/reports'),
                     :failed_dir => File.join(APP_ROOT, 'openscap/failed'),
                     :tailoring_dir => File.join(APP_ROOT, 'openscap/tailoring'),
                     :oval_content_dir => File.join(APP_ROOT, 'openscap/oval_content')
  end
end
