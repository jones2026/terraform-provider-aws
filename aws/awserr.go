package aws

import (
	"errors"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/terraform-providers/terraform-provider-aws/aws/internal/tfresource"
)

// Returns true if the error matches all these conditions:
//  * err is of type awserr.Error
//  * Error.Code() matches code
//  * Error.Message() contains message
func isAWSErr(err error, code string, message string) bool {
	var awsErr awserr.Error
	if errors.As(err, &awsErr) {
		return awsErr.Code() == code && strings.Contains(awsErr.Message(), message)
	}
	return false
}

// Returns true if the error matches all these conditions:
//  * err is of type awserr.RequestFailure
//  * RequestFailure.StatusCode() matches status code
// It is always preferable to use isAWSErr() except in older APIs (e.g. S3)
// that sometimes only respond with status codes.
func isAWSErrRequestFailureStatusCode(err error, statusCode int) bool {
	var awsErr awserr.RequestFailure
	if errors.As(err, &awsErr) {
		return awsErr.StatusCode() == statusCode
	}
	return false
}

func retryOnAwsCode(code string, f func() (interface{}, error)) (interface{}, error) {
	var resp interface{}
	err := resource.Retry(2*time.Minute, func() *resource.RetryError {
		var err error
		resp, err = f()
		if err != nil {
			awsErr, ok := err.(awserr.Error)
			if ok && awsErr.Code() == code {
				return resource.RetryableError(err)
			}
			return resource.NonRetryableError(err)
		}
		return nil
	})

	if tfresource.TimedOut(err) {
		resp, err = f()
	}

	return resp, err
}

// RetryOnAwsCodes retries AWS error codes for one minute
// Note: This function will be moved out of the aws package in the future.
func RetryOnAwsCodes(codes []string, f func() (interface{}, error)) (interface{}, error) {
	var resp interface{}
	err := resource.Retry(1*time.Minute, func() *resource.RetryError {
		var err error
		resp, err = f()
		if err != nil {
			awsErr, ok := err.(awserr.Error)
			if ok {
				for _, code := range codes {
					if awsErr.Code() == code {
						return resource.RetryableError(err)
					}
				}
			}
			return resource.NonRetryableError(err)
		}
		return nil
	})

	if tfresource.TimedOut(err) {
		resp, err = f()
	}

	return resp, err
}

var encodedFailureMessagePattern = regexp.MustCompile(`(?i)(.*) Encoded authorization failure message: ([\w-]+) ?( .*)?`)

type stsDecoder interface {
	DecodeAuthorizationMessage(input *sts.DecodeAuthorizationMessageInput) (*sts.DecodeAuthorizationMessageOutput, error)
}

// decodeError replaces encoded authorization messages with the
// decoded results
func decodeAWSError(decoder stsDecoder, err error) error {

	if err != nil {
		groups := encodedFailureMessagePattern.FindStringSubmatch(err.Error())
		if groups != nil && len(groups) > 1 {
			result, decodeErr := decoder.DecodeAuthorizationMessage(&sts.DecodeAuthorizationMessageInput{
				EncodedMessage: aws.String(groups[2]),
			})
			if decodeErr == nil {
				msg := aws.StringValue(result.DecodedMessage)
				return fmt.Errorf("%s Authorization failure message: '%s'%s", groups[1], msg, groups[3])
			}
			log.Printf("[WARN] Attempted to decode authorization message, but received: %v", decodeErr)
		}
	}
	return err
}

// makeAuthZMessageDecodingResources modifies a map of resources, replacing the individual
// Create, Read, Delete, Exists methods with wrappers that will attempt to automatically
// decode any encoded authorization messages
func makeAuthZMessageDecodingResources(resources map[string]*schema.Resource) map[string]*schema.Resource {
	for _, r := range resources {
		decodeErrorsForResource(r)
	}
	return resources
}

// creates auto-decoding wrappers around the existing resource functions
func decodeErrorsForResource(r *schema.Resource) {
	if r.Create != nil {
		create := r.Create
		r.Create = func(d *schema.ResourceData, meta interface{}) error {
			err := create(d, meta)
			return decodeAWSError(meta.(*AWSClient).stsconn, err)
		}
	}

	if r.Update != nil {
		update := r.Update
		r.Update = func(d *schema.ResourceData, meta interface{}) error {
			err := update(d, meta)
			return decodeAWSError(meta.(*AWSClient).stsconn, err)
		}
	}

	if r.Read != nil {
		read := r.Read
		r.Read = func(d *schema.ResourceData, meta interface{}) error {
			err := read(d, meta)
			return decodeAWSError(meta.(*AWSClient).stsconn, err)
		}
	}

	if r.Delete != nil {
		delete := r.Delete
		r.Delete = func(d *schema.ResourceData, meta interface{}) error {
			err := delete(d, meta)
			return decodeAWSError(meta.(*AWSClient).stsconn, err)
		}
	}

	if r.Exists != nil {
		exists := r.Exists
		r.Exists = func(d *schema.ResourceData, meta interface{}) (bool, error) {
			ok, err := exists(d, meta)
			return ok, decodeAWSError(meta.(*AWSClient).stsconn, err)
		}
	}

	if r.Importer != nil {
		state := r.Importer.State
		r.Importer.State = func(d *schema.ResourceData, meta interface{}) ([]*schema.ResourceData, error) {
			rd, err := state(d, meta)
			return rd, decodeAWSError(meta.(*AWSClient).stsconn, err)
		}
	}
}
