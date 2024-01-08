require 'smart_proxy_openscap/foreman_forwarder'

module Proxy::OpenSCAP
  class ForemanArfForwarder < ForemanForwarder
    # 下列兩個方法設為 private, 表示這兩個方法只能在本類的內部使用,並不開放給public呼叫。
    # 該類其餘的方法都在本類的父類(ForemanForwarder)中都有定義, 而唯獨下列兩個"私有方法"會因類而異。
    private  

    def parse_report(cname, policy_id, date, report_data)
      Proxy::OpenSCAP::ArfParser.new(cname, policy_id, date).as_json(report_data)
    end

    # 返回要上傳資料的目標服務器位址
    def report_upload_path(cname, policy_id, date)
      upload_path "arf_reports", cname, policy_id, date
    end
  end
end
