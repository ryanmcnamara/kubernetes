package etcd3

import (
	"github.com/coreos/etcd/clientv3"
	"github.com/coreos/etcd/mvcc/mvccpb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestParseEvent(t *testing.T) {
	for _, tc := range []struct {
		name          string
		etcdEvent     *clientv3.Event
		expectedEvent *event
		expectedErr   string
	}{
		{
			name: "successful add",
			etcdEvent: &clientv3.Event{
				Type: mvccpb.PUT,
				Kv: &mvccpb.KeyValue{
					// key is the key in bytes. An empty key is not allowed.
					Key:            []byte("key"),
					ModRevision:    1,
					CreateRevision: 1,
					Value:          []byte("value"),
				},
			},
			expectedEvent: &event{
				key:       "key",
				value:     []byte("value"),
				prevValue: nil,
				rev:       1,
				isDeleted: false,
				isCreated: true,
			},
			expectedErr: "",
		},
		{
			name: "unsuccessful delete",
			etcdEvent: &clientv3.Event{
				Type: mvccpb.DELETE,
				Kv: &mvccpb.KeyValue{
					// key is the key in bytes. An empty key is not allowed.
					Key:            []byte("key"),
					CreateRevision: 1,
					ModRevision:    2,
					Value:          nil,
				},
			},
			expectedErr: "etcd delete event has nil prevKV",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			actualEvent, err := parseEvent(tc.etcdEvent)
			if tc.expectedErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectedErr)
			} else {
				assert.Equal(t, tc.expectedEvent, actualEvent)
			}
		})
	}
}
