#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import six

from kmip.core import attributes
from kmip.core import enums
from kmip.core import primitives
from kmip.core import utils
from kmip.core import misc
from kmip.core import objects
from kmip.core.messages.payloads import base


class ImportRequestPayload(base.RequestPayload):
    """
       A request payload for the Import operation.

       Args:
           unique_identifier: The unique ID of the managed object to be used for
               import.
           object_type: The type of the object to import.
           attributes:
           symmetric_key:
       """

    def __init__(self,
                 unique_identifier=None,
                 object_type=None,
                 attributes=None,
                 symmetric_key=None,
                 authenticated_encryption_tag=None
                 ):
        super(ImportRequestPayload, self).__init__()

        self.unique_identifier = primitives.TextString(
            value=unique_identifier,
            tag=enums.Tags.UNIQUE_IDENTIFIER
        )
        self.object_type  = primitives.Enumeration(
            enums.ObjectType,
            value=object_type,
            tag=enums.Tags.OBJECT_TYPE
        )
        self.attributes = objects.Attributes(
            attributes=attributes
        )
        self.symmetric_key = symmetric_key
        self.authenticated_encryption_tag = primitives.ByteString(
            value=authenticated_encryption_tag,
            tag=enums.Tags.AUTHENTICATED_ENCRYPTION_TAG
        )

    def write(self, output_stream, kmip_version=enums.KMIPVersion.KMIP_2_0):
        local_stream = utils.BytearrayStream()
        self.unique_identifier.write(local_stream, kmip_version=kmip_version)
        self.object_type.write(local_stream, kmip_version=kmip_version)
        self.attributes.write(local_stream, kmip_version=kmip_version)
        self.symmetric_key.write(local_stream, kmip_version=kmip_version)
        self.authenticated_encryption_tag.write(local_stream, kmip_version=kmip_version)

        self.length = local_stream.length()
        super(ImportRequestPayload, self).write(
            output_stream,
            kmip_version=kmip_version
        )
        output_stream.write(local_stream.buffer)

class ImportResponsePayload(base.ResponsePayload):
    """
           A request payload for the Import operation.

           Args:
               unique_identifier: The unique ID of the managed object to be used for
                   import.
               object_type: The type of the object to import.
               attributes:
               symmetric_key:
           """

    def __init__(self,
                 unique_identifier=None):
        super(ImportResponsePayload, self).__init__()

        self._unique_identifier = None

        self.unique_identifier = unique_identifier
