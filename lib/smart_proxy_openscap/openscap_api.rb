#
# Copyright (c) 2014--2015 Red Hat Inc.
#
# This software is licensed to you under the GNU General Public License,
# version 3 (GPLv3). There is NO WARRANTY for this software, express or
# implied, including the implied warranties of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. You should have received a copy of GPLv3
# along with this software; if not, see http://www.gnu.org/licenses/gpl.txt
#
require 'smart_proxy_openscap/openscap_lib'

module Proxy::OpenSCAP
  HTTP_ERRORS = [
    EOFError,
    Errno::ECONNRESET,
    Errno::EINVAL,
    Errno::ECONNREFUSED,
    Net::HTTPBadResponse,
    Net::HTTPHeaderSyntaxError,
    Net::ProtocolError,
    Timeout::Error
  ]

  class Api < ::Sinatra::Base
    include ::Proxy::Log
    helpers ::Proxy::Helpers
    authorize_with_ssl_client
    #================================= 正則表達式 =====================================
    # "%r{ ... }" 是 Ruby 中一种表示正则表达式的字面量的特殊语法。它允许你创建一个正则表达式，而无需使用传统的斜杠 /。
    # 使用传统斜杠 : pattern1 = /^\/users\/\d+\/profile$/
    # 使用 %r     : pattern2 = %r{^/users/\d+/profile$}
    # "^" : 表示匹配字符串的开头。
    # (/arf/\d+|/policies/\d+/content/|...): 这是一个捕获组，包含多个子表达式，通过 | 连接。它匹配多个可能的路径模式。
    # /arf/\d+ ;匹配 "/arf/" 后跟至少一个数字。
    # /policies/\d+/tailoring/ ;匹配 "/policies/" 后跟至少一个数字，然后 "/tailoring/"
    CLIENT_PATHS = Regexp.compile(%r{^(/arf/\d+|/policies/\d+/content/|/policies/\d+/tailoring/|/oval_reports|/oval_policies)})

    # authorize via trusted hosts but let client paths in without such authorization  
    # 定义了一个 before 过滤器，它将在每个请求处理之前,會执行塊中的操作。
    # 这段代码的目的是在请求到达之前检查路径，如果是一些特定的路径，则直接跳过授权检查，否则执行授权逻辑。    
    before do   
      # 若條件滿足, pass 會跳过后续的过滤器或路由处理,直接返回,也不會返回nil或任何值。"=~" 运算符用于进行正则表达式匹配。
      pass if request.path_info =~ CLIENT_PATHS   # 在Sinatra中，"request" 是一个关键字，表示当前请求的相关信息。
      do_authorize_with_trusted_hosts
    end
   
    # 在请求路径匹配 "/arf/" 开头或 "/oval_reports/" 开头的路径之前，执行指定的代码块。
    before '(/arf/*|/oval_reports/*)' do
      begin
        @cn = Proxy::OpenSCAP::common_name request  # 使用 Proxy::OpenSCAP::common_name 獲取請求的公用名（common name）。這可能涉及某種形式的客戶端身份驗證或證書處理。
      # 如果發生 Proxy::Error::Unauthorized 例外，則這裡的代碼會捕獲該例外並處理。  
      # 如果發生了不是 Proxy::Error::Unauthorized 的例外，該例外將沿著異常傳播路徑繼續，可能被上層的 rescue 區塊或者最終的全局 rescue 區塊捕獲，
      # 或者如果都沒有找到相應的處理邏輯，程式將被終止。  
      rescue Proxy::Error::Unauthorized => e  
        log_halt 403, "Client authentication failed: #{e.message}"  # 它會使用 log_halt 方法記錄一條 403 Forbidden 的日誌，並包含例外的錯誤消息。然後終止請求的處理，直接返回 403 錯誤碼給客戶端。      
      end
      @reported_at = Time.now.to_i
    end

    # Route patterns may include named parameters, accessible via the params hash:
    # matches "POST /arf/foo" and "POST /arf/bar", params['name'] is 'foo' or 'bar'
    post "/arf/:policy" do
      policy = params[:policy]

      begin
        post_to_foreman = ForemanArfForwarder.new.post_report(@cn, policy, @reported_at, request.body.string, Proxy::OpenSCAP::Plugin.settings.timeout)
        Proxy::OpenSCAP::StorageFs.new(Proxy::OpenSCAP::Plugin.settings.reportsdir, @cn, post_to_foreman['id'], @reported_at).store_archive(request.body.string)
        post_to_foreman.to_json
      rescue Proxy::OpenSCAP::StoreReportError => e
        Proxy::OpenSCAP::StorageFs.new(Proxy::OpenSCAP::Plugin.settings.failed_dir, @cn, post_to_foreman['id'], @reported_at).store_failed(request.body.string)
        logger.error "Failed to save Report in reports directory (#{Proxy::OpenSCAP::Plugin.settings.reportsdir}). Failed with: #{e.message}.
                      Saving file in #{Proxy::OpenSCAP::Plugin.settings.failed_dir}. Please copy manually to #{Proxy::OpenSCAP::Plugin.settings.reportsdir}"
        { :result => 'Storage failure on proxy, see proxy logs for details' }.to_json
      rescue Nokogiri::XML::SyntaxError => e
        error = "Failed to parse Arf Report, moving to #{Proxy::OpenSCAP::Plugin.settings.corrupted_dir}"
        logger.error error
        Proxy::OpenSCAP::StorageFs.new(Proxy::OpenSCAP::Plugin.settings.corrupted_dir, @cn, policy, @reported_at).store_corrupted(request.body.string)
        { :result => (error << ' on proxy') }.to_json
      rescue *HTTP_ERRORS => e
        ### If the upload to foreman fails then store it in the spooldir
        msg = "Failed to upload to Foreman, saving in spool. Failed with: #{e.message}"
        logger.error msg
        Proxy::OpenSCAP::StorageFs.new(Proxy::OpenSCAP::Plugin.settings.spooldir, @cn, policy, @reported_at).store_spool(request.body.string)
        { :result => msg }.to_json
      rescue Proxy::OpenSCAP::StoreSpoolError => e
        log_halt 500, e.message
      rescue Proxy::OpenSCAP::ReportUploadError, Proxy::OpenSCAP::ReportDecompressError => e
        { :result => e.message }.to_json
      end
    end

    post "/oval_reports/:oval_policy_id" do
      ForemanOvalForwarder.new.post_report(@cn, params[:oval_policy_id], @reported_at, request.body.string, Plugin.settings.timeout)

      { :reported_at => Time.at(@reported_at) }.to_json
    rescue *HTTP_ERRORS => e
      msg = "Failed to upload to Foreman, failed with: #{e.message}"
      logger.error e
      { :result => msg }.to_json
    rescue Nokogiri::XML::SyntaxError => e
      logger.error e
      { :result => 'Failed to parse OVAL report, see proxy logs for details' }.to_json
    rescue Proxy::OpenSCAP::ReportUploadError, Proxy::OpenSCAP::ReportDecompressError => e
      { :result => e.message }.to_json
    end


    get "/arf/:id/:cname/:date/:digest/xml" do
      content_type 'application/x-bzip2'
      begin
        Proxy::OpenSCAP::StorageFs.new(Proxy::OpenSCAP::Plugin.settings.reportsdir, params[:cname], params[:id], params[:date]).get_arf_xml(params[:digest])
      rescue FileNotFound => e
        log_halt 500, "Could not find requested file, #{e.message}"
      end
    end

    delete "/arf/:id/:cname/:date/:digest" do
      begin
        Proxy::OpenSCAP::StorageFs.new(Proxy::OpenSCAP::Plugin.settings.reportsdir, params[:cname], params[:id], params[:date]).delete_arf_file
      rescue FileNotFound => e
        logger.debug "Could not find requested file, #{e.message} - Assuming deleted"
      end
    end

    get "/arf/:id/:cname/:date/:digest/html" do
      begin
        Proxy::OpenSCAP::OpenscapHtmlGenerator.new(params[:cname], params[:id], params[:date], params[:digest]).get_html
      rescue FileNotFound => e
        log_halt 500, "Could not find requested file, #{e.message}"
      rescue OpenSCAPException => e
        log_halt 500, "Could not generate report in HTML"
      end
    end

    get "/policies/:policy_id/content/:digest" do
      content_type 'application/xml'
      begin
        Proxy::OpenSCAP::FetchScapFile.new(:scap_content)
          .fetch(params[:policy_id], params[:digest], Proxy::OpenSCAP::Plugin.settings.contentdir)
      rescue *HTTP_ERRORS => e
        log_halt e.response.code.to_i, file_not_found_msg
      rescue StandardError => e
        log_halt 500, "Error occurred: #{e.message}"
      end
    end

    get "/policies/:policy_id/tailoring/:digest" do
      content_type 'application/xml'
      begin
        Proxy::OpenSCAP::FetchScapFile.new(:tailoring_file)
          .fetch(params[:policy_id], params[:digest], Proxy::OpenSCAP::Plugin.settings.tailoring_dir)
      rescue *HTTP_ERRORS => e
        log_halt e.response.code.to_i, file_not_found_msg
      rescue StandardError => e
        log_halt 500, "Error occurred: #{e.message}"
      end
    end

    get "/oval_policies/:oval_policy_id/oval_content/:digest" do
      content_type 'application/x-bzip2'
      begin
        Proxy::OpenSCAP::FetchScapFile.new(:oval_content)
          .fetch(params[:oval_policy_id], params[:digest], Proxy::OpenSCAP::Plugin.settings.oval_content_dir)
      rescue *HTTP => e
        log_halt e.response.code.to_i, file_not_found_msg
      rescue StandardError => e
        log_halt 500, "Error occurred: #{e.message}"
      end
    end

    post "/scap_content/policies" do      
      puts "***** 3 Joseph_say post /scap_content/policies *****"
      begin        
        Proxy::OpenSCAP::ProfilesParser.new.profiles('scap_content', request.body.string)
      rescue *HTTP_ERRORS => e
        log_halt 500, e.message
      rescue StandardError => e
        log_halt 500, "Error occurred: #{e.message}"
      end
    end

    post "/tailoring_file/profiles" do
      begin
        Proxy::OpenSCAP::ProfilesParser.new.profiles('tailoring_file', request.body.string)
      rescue *HTTP_ERRORS => e
        log_halt 500, e.message
      rescue StandardError => e
        log_halt 500, "Error occurred: #{e.message}"
      end
    end

    post "/scap_file/validator/:type" do
      puts "***** 3 Joseph_say post /scap_file/validator/:type *****"
      validate_scap_file params
    end

    post "/scap_content/validator" do
      puts "***** 3 Joseph_say post /scap_content/validator *****"
      logger.warn "DEPRECATION WARNING: '/scap_content/validator' will be removed in the future. Use '/scap_file/validator/scap_content' instead"
      params[:type] = 'scap_content'
      validate_scap_file params
    end

    post "/scap_content/guide/?:policy?" do
      begin
        Proxy::OpenSCAP::PolicyParser.new(params[:policy]).guide(request.body.string)
      rescue *HTTP_ERRORS => e
        log_halt 500, e.message
      rescue StandardError => e
        log_halt 500, "Error occurred: #{e.message}"
      end
    end

    get "/spool_errors" do
      begin
        Proxy::OpenSCAP::StorageFs.new(Proxy::OpenSCAP::Plugin.settings.corrupted_dir, nil, nil, nil).spool_errors.to_json
      rescue StandardError => e
        log_halt 500, "Error occurred: #{e.message}"
      end
    end

    private

    def validate_scap_file(params)
      begin
        Proxy::OpenSCAP::ContentParser.new.validate(params[:type], request.body.string).to_json
      rescue *HTTP_ERRORS => e
        log_halt 500, e.message
      rescue StandardError => e
        log_halt 500, "Error occurred: #{e.message}"
      end
    end

    def file_not_found_msg
      "File not found on Foreman. Wrong policy id?"
    end
  end
end
