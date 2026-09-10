UPDATE sis_formato_reportes
SET URL = 'CotizacionVentaTY.jasper', REPORTE = 'CotizacionVentaTY.jasper'
WHERE no_cia = 'TY'
AND modulo = '3'
AND formulario = 'PROFORMAS';

UPDATE sis_formato_reportes
SET URL = 'CotizacionVentaExoneradoTY.jasper', REPORTE = 'CotizacionVentaExoneradoTY.jasper'
WHERE no_cia = 'TY'
AND modulo = '70'
AND formulario = 'PROFORMAS';