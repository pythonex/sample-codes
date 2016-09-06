from structlog import get_logger

from rest_framework.mixins import (
    CreateModelMixin as StockCreateModelMixin,
    DestroyModelMixin as StockDestroyModelMixin,
    UpdateModelMixin as StockUpdateModelMixin,
    ListModelMixin, RetrieveModelMixin,
)
from rest_framework.viewsets import GenericViewSet


log = get_logger('renooit')


class UpdateModelMixin(StockUpdateModelMixin):
    """
    DRF mixin with added logging capabilities.
    """
    def perform_update(self, serializer):
        super(UpdateModelMixin, self).perform_update(serializer)
        log.info(
            '{}.{}'.format(
                serializer.instance.__class__.__name__.lower(),
                self.action
            ),
            user=self.request.user.pk if self.request.user else "",
            object=serializer.instance.pk,
        )


class CreateModelMixin(StockCreateModelMixin):
    """
    DRF mixin with added logging capabilities.
    """
    def perform_create(self, serializer):
        super(CreateModelMixin, self).perform_create(serializer)
        log.info(
            '{}.{}'.format(
                serializer.instance.__class__.__name__.lower(),
                self.action
            ),
            user=self.request.user.pk if self.request.user else "",
            object=serializer.instance.pk,
        )


class DestroyModelMixin(StockDestroyModelMixin):
    """
    DRF mixin with added logging capabilities.
    """
    def perform_destroy(self, instance):
        log.info(
            '{}.{}'.format(
                instance.__class__.__name__.lower(),
                self.action
            ),
            user=self.request.user.pk if self.request.user else "",
            object=instance.pk,
        )
        super(DestroyModelMixin, self).perform_destroy(instance)


class ModelViewSet(CreateModelMixin, RetrieveModelMixin, UpdateModelMixin,
                   DestroyModelMixin, ListModelMixin, GenericViewSet):
    pass
