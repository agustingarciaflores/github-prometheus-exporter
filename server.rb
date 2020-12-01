require 'sinatra'
require 'octokit'
require 'dotenv/load' # Manages environment variables
require 'json'
require 'openssl'     # Verifies the webhook signature
require 'jwt'         # Authenticates a GitHub App
require 'time'        # Gets ISO 8601 representation of a Time object
require 'logger'      # Logs debug statements
require 'prometheus/client'
require 'prometheus/client/push'

set :port, 3000
set :bind, '0.0.0.0'


# This is template code to create a GitHub App server.
# You can read more about GitHub Apps here: # https://developer.github.com/apps/
#
# On its own, this app does absolutely nothing, except that it can be installed.
# It's up to you to add functionality!
# You can check out one example in advanced_server.rb.
#
# This code is a Sinatra app, for two reasons:
#   1. Because the app will require a landing page for installation.
#   2. To easily handle webhook events.
#
# Of course, not all apps need to receive and process events!
# Feel free to rip out the event handling code if you don't need it.
#
# Have fun!
#

module GithubMetrics 
  def self.repoTotalCommits(repoOwner, repoName)
    query = <<-GRAPHQL
    query($repoOwner: String!, $repoName: String!) {
      repository(owner: $repoOwner, name:$repoName) {
        object(expression:"master") {
          ... on Commit {
            history {
              totalCount
            }
          }
        }
      }
    }
    GRAPHQL

    variables = {
      'repoOwner': repoOwner,
      'repoName': repoName
    }

    return { query: query, variables: variables}.to_json

  end

  def self.repoTotalIssues(repoOwner, repoName) 
    query = <<-GRAPHQL
    query($repoOwner: String!, $repoName: String!) {
      repository(owner: $repoOwner, name:$repoName) {
        issues (first: 100) {
          totalCount
        }
      }
    }
    GRAPHQL

    variables = {
      'repoOwner': repoOwner,
      'repoName': repoName 
    }

    return { query: query, variables: variables}.to_json

  end

  def self.repoTotalPullRequests(repoOwner, repoName)
    query = <<-GRAPHQL
    query($repoOwner: String!, $repoName: String!) {
      repository(owner: $repoOwner, name:$repoName) {
        pullRequests(first: 100) {
          totalCount
        }
      }
    }
    GRAPHQL

    variables = {
      'repoOwner': repoOwner,
      'repoName': repoName
    }

    return { query: query, variables: variables}.to_json

  end

  def self.repoOpenPullRequests(repoOwner, repoName)
    query = <<-GRAPHQL
    query($repoOwner: String!, $repoName: String!) {
      repository(owner: $repoOwner, name:$repoName) {
        pullRequests(first: 100, states: OPEN) {
          totalCount
        }
      }
    }
    GRAPHQL

    variables = {
      'repoOwner': repoOwner,
      'repoName': repoName
    }

    return { query: query, variables: variables}.to_json

  end

  def self.repoClosedPullRequests(repoOwner, repoName)
    query = <<-GRAPHQL
    query($repoOwner: String!, $repoName: String!) {
      repository(owner: $repoOwner, name:$repoName) {
        pullRequests(first: 100, states: CLOSED) {
          totalCount
        }
      }
    }
    GRAPHQL

    variables = {
      'repoOwner': repoOwner,
      'repoName': repoName
    }

    return { query: query, variables: variables}.to_json

  end

  def self.repoMergedPullRequests(repoOwner, repoName)
    query = <<-GRAPHQL
    query($repoOwner: String!, $repoName: String!) {
      repository(owner: $repoOwner, name:$repoName) {
        pullRequests(first: 100, states: MERGED) {
          totalCount
        }
      }
    }      
    GRAPHQL

    variables = {
      'repoOwner': repoOwner,
      'repoName': repoName
    }

    return { query: query, variables: variables}.to_json

  end

  def self.developerContributions(repoOwner, repoName, contribType)
      
    commitBool = false
    issueBool = false
    prBool = false
    metricName = nil

    case contribType
    when 'commit'
      commitBool = true
      metricName = 'totalCommitContributions'
    when 'issue'
      issueBool = true
      metricName = 'totalIssueContributions'
    when 'pr'
      prBool = true
      metricName = 'totalPullRequestContributions'
    end
      
    query = <<-GRAPHQL
    query($repoOwner: String!, $repoName: String!, $commitBool: Boolean!, $issueBool: Boolean!, $prBool: Boolean!) {
      repository(owner: $repoOwner, name:$repoName) {
        name
        id
        collaborators (first: 100) {
          nodes {
            name
            contributionsCollection @include(if: $commitBool) {
              totalCommitContributions
            }
            contributionsCollection @include(if: $issueBool) {
              totalIssueContributions
            }
            contributionsCollection @include(if: $prBool) {
              totalPullRequestContributions
            }
          }
        }
      }
    }
    GRAPHQL

    variables = {
      'repoOwner': repoOwner,
      'repoName': repoName,
      'commitBool': commitBool,
      'issueBool': issueBool,
      'prBool': prBool
    }

    return { query: query, variables: variables}.to_json
  end   

end

class GHAapp < Sinatra::Application

  # Expects that the private key in PEM format. Converts the newlines
  PRIVATE_KEY = OpenSSL::PKey::RSA.new(ENV['GITHUB_PRIVATE_KEY'].gsub('\n', "\n"))

  # Your registered app must have a secret set. The secret is used to verify
  # that webhooks are sent by GitHub.
  WEBHOOK_SECRET = ENV['GITHUB_WEBHOOK_SECRET']

  # The GitHub App's identifier (type integer) set when registering an app.
  APP_IDENTIFIER = ENV['GITHUB_APP_IDENTIFIER']


  REPO_OWNER = ENV['REPO_OWNER']
  REPO_NAME = ENV['REPO_NAME']

  PUSHGATEWAY_URL = ENV['PUSHGATEWAY_URL']

  # Turn on Sinatra's verbose logging during development
  configure :development do
    set :logging, Logger::DEBUG
  end


  # Before each request to the `/event_handler` route
  before '/event_handler' do
    get_payload_request(request)
    verify_webhook_signature
    authenticate_app
    # Authenticate the app installation in order to run API operations
    authenticate_installation(@payload)
  end


  post '/event_handler' do

    # # # # # # # # # # # #
    # ADD YOUR CODE HERE  #
    # # # # # # # # # # # #

    # Always update developer contributions
    case request.env['HTTP_X_GITHUB_EVENT']
    when 'push'
      update_total_commit_number(@payload)
      update_developer_contributions(@payload, 'commit')
    when 'issues'
      update_total_issues_number(@payload)
      update_developer_contributions(@payload, 'issue')
    when 'pull_request'
      if @payload['action'] === 'opened'
        update_total_prs(@payload)
        update_open_prs(@payload)
        update_developer_contributions(@payload, 'pr')
      elsif @payload['action'] === 'closed'
        update_closed_prs(@payload)
        if @payload['merged'] == true
          update_merged_prs(@payload)
        end
      end
    end
    200 # success status
  end


  helpers do

    # # # # # # # # # # # # # # # # #
    # ADD YOUR HELPER METHODS HERE  #
    # # # # # # # # # # # # # # # # #
    def update_total_commit_number(payload)
      json = GithubMetrics.repoTotalCommits(REPO_OWNER, REPO_NAME)

      response = @installation_client.post '/api/graphql', json

      registry = Prometheus::Client.registry

      metricName = ":" + REPO_OWNER + '_' + REPO_NAME + '_total_commits'
      metric = metricName.to_sym
      labelString = 'agustingarciaflores_hygieia_poc' + "_total_commits"
      label = labelString.to_sym

      commits = registry.gauge(:metric, docstring: '...', labels: [:label])
      commits.set(response.data[:repository][:object][:history][:totalCount], labels: [:label])
      
      Prometheus::Client::Push.new('github', labelString, PUSHGATEWAY_URL).add(registry)
      logger.debug(response.data[:repository][:object][:history][:totalCount])

    end

    def update_total_issues_number(payload)
      json = GithubMetrics.repoTotalIssues('agustingarciaflores', 'flask-demo')

      response = @installation_client.post '/api/graphql', json
      logger.debug(response.data[:repository][:issues])
    end

    def update_total_prs(payload)
      json = GithubMetrics.repoTotalPullRequests('agustingarciaflores', 'flask-demo')

      response = @installation_client.post '/api/graphql', json
      logger.debug(response.data[:repository][:pullRequests][:totalCount])
    end

    def update_open_prs(payload)
      json = GithubMetrics.repoOpenPullRequests('agustingarciaflores', 'flask-demo')

      response = @installation_client.post '/api/graphql', json
      logger.debug(response.data[:repository][:pullRequests][:totalCount])
    end

    def update_closed_prs(payload)
      json = GithubMetrics.repoClosedPullRequests('agustingarciaflores', 'flask-demo')

      response = @installation_client.post '/api/graphql', json
      logger.debug(response.data[:repository][:pullRequests][:totalCount])
    end

    def update_merged_prs(payload)
      json = GithubMetrics.repoMergedPullRequests('agustingarciaflores', 'flask-demo')

      response = @installation_client.post '/api/graphql', json
      logger.debug(response.data[:repository][:pullRequests][:totalCount])
    end

    def update_developer_contributions(payload, metricName)
      json = GithubMetrics.developerContributions('agustingarciaflores', 'flask-demo','issue')

      response = @installation_client.post '/api/graphql', json

      parsedResponse = response.data[:repository][:collaborators][:nodes]
      developers = []

      case metricName
      when 'commit'
        metricFullName = 'totalCommitContributions'
      when 'issue'
        metricFullName = 'totalIssueContributions'
      when 'pr'
        metricFullName = 'totalPullRequestContributions'
      end

      for developer in parsedResponse
        case metricName
        when 'commit'
          developers.push({'Name': developer[:name], 'contributions': developer[:contributionsCollection][:totalCommitContributions]})
        when 'issue'
          developers.push({'Name': developer[:name], 'contributions': developer[:contributionsCollection][:totalIssueContributions]})
        when 'pr'
          developers.push({'Name': developer[:name], 'contributions': developer[:contributionsCollection][:totalPullRequestContributions]})
        end
      end
      
      logger.debug(developers)
    end

    # Saves the raw payload and converts the payload to JSON format
    def get_payload_request(request)
      # request.body is an IO or StringIO object
      # Rewind in case someone already read it
      request.body.rewind
      # The raw text of the body is required for webhook signature verification
      @payload_raw = request.body.read
      begin
        @payload = JSON.parse @payload_raw
      rescue => e
        fail  "Invalid JSON (#{e}): #{@payload_raw}"
      end
    end

    # Instantiate an Octokit client authenticated as a GitHub App.
    # GitHub App authentication requires that you construct a
    # JWT (https://jwt.io/introduction/) signed with the app's private key,
    # so GitHub can be sure that it came from the app and wasn't alterered by
    # a malicious third party.
    def authenticate_app
      payload = {
          # The time that this JWT was issued, _i.e._ now.
          iat: Time.now.to_i,

          # JWT expiration time (10 minute maximum)
          exp: Time.now.to_i + (10 * 60),

          # Your GitHub App's identifier number
          iss: APP_IDENTIFIER
      }

      # Cryptographically sign the JWT.
      jwt = JWT.encode(payload, PRIVATE_KEY, 'RS256')

      # Create the Octokit client, using the JWT as the auth token.
      @app_client ||= Octokit::Client.new(bearer_token: jwt)
    end

    # Instantiate an Octokit client, authenticated as an installation of a
    # GitHub App, to run API operations.
    def authenticate_installation(payload)
      @installation_id = payload['installation']['id']
      @installation_token = @app_client.create_app_installation_access_token(@installation_id)[:token]
      
      @installation_client = Octokit::Client.new(bearer_token: @installation_token)
    end

    # Check X-Hub-Signature to confirm that this webhook was generated by
    # GitHub, and not a malicious third party.
    #
    # GitHub uses the WEBHOOK_SECRET, registered to the GitHub App, to
    # create the hash signature sent in the `X-HUB-Signature` header of each
    # webhook. This code computes the expected hash signature and compares it to
    # the signature sent in the `X-HUB-Signature` header. If they don't match,
    # this request is an attack, and you should reject it. GitHub uses the HMAC
    # hexdigest to compute the signature. The `X-HUB-Signature` looks something
    # like this: "sha1=123456".
    # See https://developer.github.com/webhooks/securing/ for details.
    def verify_webhook_signature
      their_signature_header = request.env['HTTP_X_HUB_SIGNATURE'] || 'sha1='
      method, their_digest = their_signature_header.split('=')
      our_digest = OpenSSL::HMAC.hexdigest(method, WEBHOOK_SECRET, @payload_raw)
      halt 401 unless their_digest == our_digest

      # The X-GITHUB-EVENT header provides the name of the event.
      # The action value indicates the which action triggered the event.
      logger.debug "---- received event #{request.env['HTTP_X_GITHUB_EVENT']}"
      logger.debug "----    action #{@payload['action']}" unless @payload['action'].nil?
    end

  end

  # Finally some logic to let us run this server directly from the command line,
  # or with Rack. Don't worry too much about this code. But, for the curious:
  # $0 is the executed file
  # __FILE__ is the current file
  # If they are the same—that is, we are running this file directly, call the
  # Sinatra run method
  run! if __FILE__ == $0
end
