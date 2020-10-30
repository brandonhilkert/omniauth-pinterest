require 'omniauth-oauth2'

module OmniAuth
  module Strategies
    class Pinterest < OmniAuth::Strategies::OAuth2
      option :client_options, {
        :site          => 'https://api.pinterest.com/',
        :authorize_url => 'https://www.pinterest.com/oauth/',
        :token_url     => 'https://api.pinterest.com/v3/oauth/access_token/'
      }

      def request_phase
        options[:scope]         ||= 'read_users'
        options[:response_type] ||= 'code'
        super
      end

      uid { raw_info['id'] }

      info { raw_info }

      def raw_info
        @raw_info ||= access_token.get('/v3/users/me/').parsed['data']
      end

      def ssl?
        true
      end

      private

      def callback_url
        options[:redirect_uri] || (full_host + script_name + callback_path)
      end
    end
  end
end
